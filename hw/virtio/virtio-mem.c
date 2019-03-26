/*
 * Virtio MEM device
 *
 * Copyright (C) 2018-2019 Red Hat, Inc.
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/iov.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "sysemu/kvm.h"
#include "sysemu/numa.h"
#include "sysemu/balloon.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-access.h"
#include "hw/virtio/virtio-mem.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "exec/ram_addr.h"
#include "migration/postcopy-ram.h"
#include "migration/misc.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "config-devices.h"

/*
 * Use QEMU_VMALLOC_ALIGN, so no THP will have to be split when unplugging
 * memory.
 */
#define VIRTIO_MEM_DEFAULT_BLOCK_SIZE QEMU_VMALLOC_ALIGN
#define VIRTIO_MEM_MIN_BLOCK_SIZE QEMU_VMALLOC_ALIGN
/*
 * Size the usable region slightly bigger than the requested size if
 * possible. This allows guests to make use of most requested memory even
 * if the memory region in guest physical memory has strange alignment.
 * E.g. x86-64 has alignment requirements for sections of 128 MiB.
 */
#define VIRTIO_MEM_USABLE_EXTENT (256 * MiB)

static bool virtio_mem_busy(void)
{
    /*
     * Better don't mess with dumps and migration - especially when
     * resizing memory regions. Also, RDMA migration pins all memory.
     */
    if (!migration_is_idle()) {
        return true;
    }
    if (dump_in_progress()) {
        return true;
    }
    /*
     * We can't use madvise(DONTNEED) e.g. with certain VFIO devices,
     * also resizing memory regions might be problematic. Bad thing is,
     * this might change suddenly, e.g. when hotplugging a VFIO device.
     */
    if (qemu_balloon_is_inhibited()) {
        return true;
    }
    return false;
}

static bool virtio_mem_test_bitmap(VirtIOMEM *vm, uint64_t start_gpa,
                                   uint64_t size, bool plug)
{
    uint64_t bit = (start_gpa - vm->addr) / vm->block_size;

    g_assert(QEMU_IS_ALIGNED(start_gpa, vm->block_size));
    g_assert(QEMU_IS_ALIGNED(size, vm->block_size));
    g_assert(vm->bitmap);

    while (size) {
        g_assert((bit / BITS_PER_BYTE) <= vm->bitmap_size);

        if (plug && !test_bit(bit, vm->bitmap)) {
            return false;
        } else if (!plug && test_bit(bit, vm->bitmap)) {
            return false;
        }
        size -= vm->block_size;
        bit++;
    }
    return true;
}

static void virtio_mem_set_bitmap(VirtIOMEM *vm, uint64_t start_gpa,
                                  uint64_t size, bool plug)
{
    const uint64_t bit = (start_gpa - vm->addr) / vm->block_size;
    const uint64_t nbits = size / vm->block_size;

    g_assert(QEMU_IS_ALIGNED(start_gpa, vm->block_size));
    g_assert(QEMU_IS_ALIGNED(size, vm->block_size));
    g_assert(vm->bitmap);

    if (plug) {
        bitmap_set(vm->bitmap, bit, nbits);
    } else {
        bitmap_clear(vm->bitmap, bit, nbits);
    }
}

static void virtio_mem_set_block_state(VirtIOMEM *vm, uint64_t start_gpa,
                                       uint64_t size, bool plug)
{
    const uint64_t offset = start_gpa - vm->addr;

    g_assert(start_gpa + size > start_gpa);
    g_assert(QEMU_IS_ALIGNED(start_gpa, vm->block_size));
    g_assert(size && QEMU_IS_ALIGNED(size, vm->block_size));
    if (!plug) {
        ram_block_discard_range(vm->memdev->mr.ram_block, offset, size);
    }

    virtio_mem_set_bitmap(vm, start_gpa, size, plug);
}

static void virtio_mem_send_response(VirtIOMEM *vm, VirtQueueElement *elem,
                                     struct virtio_mem_resp *resp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(vm);
    VirtQueue *vq = vm->vq;

    iov_from_buf(elem->in_sg, elem->in_num, 0, resp, sizeof(*resp));

    virtqueue_push(vq, elem, sizeof(*resp));
    virtio_notify(vdev, vq);
}

static void virtio_mem_send_response_simple(VirtIOMEM *vm,
                                            VirtQueueElement *elem,
                                            uint16_t type)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(vm);
    struct virtio_mem_resp resp = {};

    virtio_stw_p(vdev, &resp.type, type);
    virtio_mem_send_response(vm, elem, &resp);
}

static void virtio_mem_bad_request(VirtIOMEM *vm, const char *msg)
{
    virtio_error(VIRTIO_DEVICE(vm), "virtio-mem protocol violation: %s", msg);
}

static bool virtio_mem_valid_range(VirtIOMEM *vm, uint64_t gpa, uint64_t size)
{
    /* address properly aligned? */
    if (!QEMU_IS_ALIGNED(gpa, vm->block_size)) {
            return false;
    }

    /* reasonable size */
    if (gpa + size <= gpa || size == 0) {
        return false;
    }

    /* start address in usable range? */
    if (gpa < vm->addr ||
        gpa >= vm->addr + vm->usable_region_size) {
        return false;
    }

    /* end address in usable range? */
    if (gpa + size - 1 >= vm->addr + vm->usable_region_size) {
        return false;
    }
    return true;
}

static int virtio_mem_state_change_request(VirtIOMEM *vm, uint64_t gpa,
                                           uint16_t nb_blocks, bool plug)
{
    const uint64_t size = nb_blocks * vm->block_size;

    if (!virtio_mem_valid_range(vm, gpa, size)) {
        return VIRTIO_MEM_RESP_ERROR;
    }

    /* trying to plug more than requested */
    if (plug && (vm->size + size > vm->requested_size)) {
        return VIRTIO_MEM_RESP_NACK;
    }

    /* sometimes we cannot discard blocks */
    if (virtio_mem_busy()) {
        return VIRTIO_MEM_RESP_BUSY;
    }

    /* test if really all blocks are in the opposite state */
    if (!virtio_mem_test_bitmap(vm, gpa, size, !plug)) {
        return VIRTIO_MEM_RESP_ERROR;
    }

    /* update the block state */
    virtio_mem_set_block_state(vm, gpa, size, plug);

    /* update the size */
    if (plug) {
        vm->size += size;
    } else {
        vm->size -= size;
    }
    return VIRTIO_MEM_RESP_ACK;
}

static void virtio_mem_plug_request(VirtIOMEM *vm, VirtQueueElement *elem,
                                    struct virtio_mem_req *req)
{
    const uint64_t gpa = le64_to_cpu(req->u.plug.addr);
    const uint16_t nb_blocks = le16_to_cpu(req->u.plug.nb_blocks);
    uint16_t type;

    type = virtio_mem_state_change_request(vm, gpa, nb_blocks, true);
    virtio_mem_send_response_simple(vm, elem, type);
}

static void virtio_mem_unplug_request(VirtIOMEM *vm, VirtQueueElement *elem,
                                      struct virtio_mem_req *req)
{
    const uint64_t gpa = le64_to_cpu(req->u.unplug.addr);
    const uint16_t nb_blocks = le16_to_cpu(req->u.unplug.nb_blocks);
    uint16_t type;

    type = virtio_mem_state_change_request(vm, gpa, nb_blocks, false);
    virtio_mem_send_response_simple(vm, elem, type);
}

/*
 * Unplug all memory and shrink the usable region.
 */
static void virtio_mem_unplug_all(VirtIOMEM *vm)
{
    if (vm->size) {
        virtio_mem_set_block_state(vm, vm->addr,
                                   memory_region_size(&vm->memdev->mr), false);
        vm->size = 0;
    }
    vm->usable_region_size = MIN(memory_region_size(&vm->memdev->mr),
                                 vm->requested_size + VIRTIO_MEM_USABLE_EXTENT);
}

static void virtio_mem_unplug_all_request(VirtIOMEM *vm, VirtQueueElement *elem)
{

    if (virtio_mem_busy()) {
        virtio_mem_send_response_simple(vm, elem,  VIRTIO_MEM_RESP_BUSY);
        return;
    }

    virtio_mem_unplug_all(vm);
    virtio_mem_send_response_simple(vm, elem,  VIRTIO_MEM_RESP_ACK);
}

static void virtio_mem_state_request(VirtIOMEM *vm, VirtQueueElement *elem,
                                     struct virtio_mem_req *req)
{
    const uint64_t gpa = le64_to_cpu(req->u.state.addr);
    const uint16_t nb_blocks = le16_to_cpu(req->u.state.nb_blocks);
    const uint64_t size = nb_blocks * vm->block_size;
    VirtIODevice *vdev = VIRTIO_DEVICE(vm);
    struct virtio_mem_resp resp = {};

    if (!virtio_mem_valid_range(vm, gpa, size)) {
        virtio_mem_send_response_simple(vm, elem, VIRTIO_MEM_RESP_ERROR);
        return;
    }

    virtio_stw_p(vdev, &resp.type, VIRTIO_MEM_RESP_ACK);
    if (virtio_mem_test_bitmap(vm, gpa, size, true)) {
        virtio_stw_p(vdev, &resp.u.state.state, VIRTIO_MEM_STATE_PLUGGED);
    } else if (virtio_mem_test_bitmap(vm, gpa, size, false)) {
        virtio_stw_p(vdev, &resp.u.state.state, VIRTIO_MEM_STATE_UNPLUGGED);
    } else {
        virtio_stw_p(vdev, &resp.u.state.state, VIRTIO_MEM_STATE_MIXED);
    }
    virtio_mem_send_response(vm, elem, &resp);
}

static void virtio_mem_handle_request(VirtIODevice *vdev, VirtQueue *vq)
{
    const int len = sizeof(struct virtio_mem_req);
    VirtIOMEM *vm = VIRTIO_MEM(vdev);
    VirtQueueElement *elem;
    struct virtio_mem_req req;
    uint64_t type;

    elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
    if (!elem) {
        return;
    }

    if (iov_to_buf(elem->out_sg, elem->out_num, 0, &req, len) < len) {
        virtio_mem_bad_request(vm, "invalid request size");
        goto out_free;
    }

    if (iov_size(elem->in_sg, elem->in_num) < sizeof(struct virtio_mem_resp)) {
        virtio_mem_bad_request(vm, "not enough space for response");
        goto out_free;
    }

    type = le16_to_cpu(req.type);
    switch (type) {
    case VIRTIO_MEM_REQ_PLUG:
        virtio_mem_plug_request(vm, elem, &req);
        break;
    case VIRTIO_MEM_REQ_UNPLUG:
        virtio_mem_unplug_request(vm, elem, &req);
        break;
    case VIRTIO_MEM_REQ_UNPLUG_ALL:
        virtio_mem_unplug_all_request(vm, elem);
        break;
    case VIRTIO_MEM_REQ_STATE:
        virtio_mem_state_request(vm, elem, &req);
        break;
    default:
        virtio_mem_bad_request(vm, "unknown request type");
        goto out_free;
    }

out_free:
    g_free(elem);
}

static void virtio_mem_get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    VirtIOMEM *vm = VIRTIO_MEM(vdev);
    struct virtio_mem_config *config = (void *) config_data;

    config->block_size = cpu_to_le32(vm->block_size);
    config->node_id = cpu_to_le16(vm->node);
    config->requested_size = cpu_to_le64(vm->requested_size);
    config->plugged_size = cpu_to_le64(vm->size);
    config->addr = cpu_to_le64(vm->addr);
    config->region_size = cpu_to_le64(memory_region_size(&vm->memdev->mr));
    config->usable_region_size = cpu_to_le64(vm->usable_region_size);
}

static uint64_t virtio_mem_get_features(VirtIODevice *vdev, uint64_t features,
                                        Error **errp)
{
    MachineState *ms = MACHINE(qdev_get_machine());

    if (ms->numa_state) {
#if defined(CONFIG_ACPI)
        virtio_add_feature(&features, VIRTIO_MEM_F_ACPI_PXM);
#endif
    }
    return features;
}

static void virtio_mem_system_reset(void *opaque)
{
    VirtIOMEM *vm = VIRTIO_MEM(opaque);

    /*
     * During usual resets, we will unplug all memory and shrink the usable
     * region size. This is, however, not possible in all scenarios. Then,
     * the guest has to deal with this manually (VIRTIO_MEM_REQ_UNPLUG_ALL).
     */
    if (virtio_mem_busy()) {
        return;
    }

    virtio_mem_unplug_all(vm);
}

static int virtio_mem_postcopy_notifier(NotifierWithReturn *notifier,
                                        void *opaque)
{
    struct PostcopyNotifyData *pnd = opaque;

    /*
     * TODO: We cannot use madvise(DONTNEED) with concurrent postcopy. While
     *       can simply tell the guest to retry later on plug/unplug requests,
     *       system resets + restoring the unplugged state during migration
     *       requires more thought.
     *
     *       We will have to delay such activity until postcopy is finished and
     *       (notifies us via its notifier) and then restore the unplugged
     *       state. When we switch to userfaultfd (WP), we will temporarily
     *       have to unregister our userfaultfd handler when postcopy is
     *       about to start and reregister when postcopy is finished.
     */
    switch (pnd->reason) {
    case POSTCOPY_NOTIFY_PROBE:
        error_setg(pnd->errp, "virtio-mem does not support postcopy yet");
        return -ENOENT;
    default:
        break;
    }
    return 0;
}

static void virtio_mem_device_realize(DeviceState *dev, Error **errp)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    int nb_numa_nodes = ms->numa_state ? ms->numa_state->num_nodes : 0;
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOMEM *vm = VIRTIO_MEM(dev);
    Error *local_err = NULL;
    uint64_t page_size;

    /* verify the memdev */
    if (!vm->memdev) {
        error_setg(&local_err, "'%s' property must be set",
                   VIRTIO_MEM_MEMDEV_PROP);
        goto out;
    } else if (host_memory_backend_is_mapped(vm->memdev)) {
        char *path = object_get_canonical_path_component(OBJECT(vm->memdev));

        error_setg(&local_err, "can't use already busy memdev: %s", path);
        g_free(path);
        goto out;
    }

    /* verify the node */
    if ((nb_numa_nodes && vm->node >= nb_numa_nodes) ||
        (!nb_numa_nodes && vm->node)) {
        error_setg(&local_err, "Property '%s' has value '%" PRIu32
                   "', which exceeds the number of numa nodes: %d",
                   VIRTIO_MEM_NODE_PROP, vm->node,
                   nb_numa_nodes ? nb_numa_nodes : 1);
        goto out;
    }

    /* mmap/madvise changes have to be reflected in guest physical memory */
    if (kvm_enabled() && !kvm_has_sync_mmu()) {
        error_set(&local_err, ERROR_CLASS_KVM_MISSING_CAP,
                  "Using KVM without synchronous MMU, virtio-mem unavailable");
        goto out;
    }

    /*
     * TODO: madvise(DONTNEED) does not work with mlock. We might be able
     * to temporarily unlock and relock at the right places to make it work.
     */
    if (enable_mlock) {
        error_setg(&local_err, "Memory is locked, virtio-mem unavailable");
        goto out;
    }

    g_assert(memory_region_is_ram(&vm->memdev->mr));
    g_assert(!memory_region_is_rom(&vm->memdev->mr));
    g_assert(vm->memdev->mr.ram_block);

    /*
     * TODO: Huge pages under Linux don't support the zero page, therefore
     * dump and migration could result in a high memory consumption. Disallow
     * it.
     */
    page_size = qemu_ram_pagesize(vm->memdev->mr.ram_block);
    if (page_size != getpagesize()) {
        error_setg(&local_err, "'%s' page size (0x%" PRIx64 ") not supported",
                   VIRTIO_MEM_MEMDEV_PROP, page_size);
        goto out;
    }

    /* now that memdev and block_size is fixed, verify the properties */
    if (vm->block_size < page_size) {
        error_setg(&local_err, "'%s' has to be at least the page size (0x%"
                   PRIx64 ")", VIRTIO_MEM_BLOCK_SIZE_PROP, page_size);
        goto out;
    } else if (!QEMU_IS_ALIGNED(vm->requested_size, vm->block_size)) {
        error_setg(errp, "'%s' has to be multiples of '%s' (0x%" PRIx32
                   ")", VIRTIO_MEM_REQUESTED_SIZE_PROP,
                   VIRTIO_MEM_BLOCK_SIZE_PROP, vm->block_size);
    } else if (!QEMU_IS_ALIGNED(memory_region_size(&vm->memdev->mr),
                                vm->block_size)) {
        error_setg(&local_err, "'%s' size has to be multiples of '%s' (0x%"
                   PRIx32 ")", VIRTIO_MEM_MEMDEV_PROP,
                   VIRTIO_MEM_BLOCK_SIZE_PROP, vm->block_size);
        goto out;
    }

    /*
     * If possible, we size the usable region a little bit bigger than the
     * requested size, so the guest has more flexibility.
     */
    vm->usable_region_size = MIN(memory_region_size(&vm->memdev->mr),
                                 vm->requested_size + VIRTIO_MEM_USABLE_EXTENT);

    /* allocate the bitmap for tracking the state of a block */
    vm->bitmap_size = memory_region_size(&vm->memdev->mr) / vm->block_size;
    vm->bitmap = bitmap_new(vm->bitmap_size);

    /* all memory is unplugged initially */
    virtio_mem_set_block_state(vm, vm->addr,
                               memory_region_size(&vm->memdev->mr), false);

    /* setup the virtqueue */
    virtio_init(vdev, TYPE_VIRTIO_MEM, VIRTIO_ID_MEM,
                sizeof(struct virtio_mem_config));
    vm->vq = virtio_add_queue(vdev, 128, virtio_mem_handle_request);

    host_memory_backend_set_mapped(vm->memdev, true);
    vmstate_register_ram(&vm->memdev->mr, DEVICE(vm));
    vm->postcopy_notifier.notify = virtio_mem_postcopy_notifier;
    postcopy_add_notifier(&vm->postcopy_notifier);
    qemu_register_reset(virtio_mem_system_reset, vm);
out:
    error_propagate(errp, local_err);
}

static void virtio_mem_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOMEM *vm = VIRTIO_MEM(dev);

    qemu_unregister_reset(virtio_mem_system_reset, vm);
    postcopy_remove_notifier(&vm->postcopy_notifier);
    vmstate_unregister_ram(&vm->memdev->mr, DEVICE(vm));
    host_memory_backend_set_mapped(vm->memdev, false);
    virtio_del_queue(vdev, 128);
    virtio_cleanup(vdev);
    g_free(vm->bitmap);
}

static int virtio_mem_pre_save(void *opaque)
{
    VirtIOMEM *vm = VIRTIO_MEM(opaque);

    vm->migration_addr = vm->addr;
    vm->migration_block_size = vm->block_size;

    return 0;
}

static int virtio_mem_restore_unplugged(VirtIOMEM *vm)
{
    unsigned long bit;
    uint64_t gpa;

    /*
     * Called after all migrated memory has been restored, but before postcopy
     * is enabled. Either way, we have to restore our state from the bitmap
     * first.
     */
    bit = find_first_zero_bit(vm->bitmap, vm->bitmap_size);
    while (bit < vm->bitmap_size) {
        gpa = vm->addr + bit * vm->block_size;

        virtio_mem_set_block_state(vm, gpa, vm->block_size, false);
        bit = find_next_zero_bit(vm->bitmap, vm->bitmap_size, bit + 1);
    }

    return 0;
}

static int virtio_mem_post_load(void *opaque, int version_id)
{
    VirtIOMEM *vm = VIRTIO_MEM(opaque);

    if (vm->migration_block_size != vm->block_size) {
        error_report("'%s' doesn't match", VIRTIO_MEM_BLOCK_SIZE_PROP);
        return -EINVAL;
    }
    if (vm->migration_addr != vm->addr) {
        error_report("'%s' doesn't match", VIRTIO_MEM_ADDR_PROP);
        return -EINVAL;
    }
    return virtio_mem_restore_unplugged(vm);
}

static const VMStateDescription vmstate_virtio_mem_device = {
    .name = "virtio-mem-device",
    .minimum_version_id = 1,
    .version_id = 1,
    .pre_save = virtio_mem_pre_save,
    .post_load = virtio_mem_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64(usable_region_size, VirtIOMEM),
        VMSTATE_UINT64(size, VirtIOMEM),
        VMSTATE_UINT64(requested_size, VirtIOMEM),
        VMSTATE_UINT64(migration_addr, VirtIOMEM),
        VMSTATE_UINT32(migration_block_size, VirtIOMEM),
        VMSTATE_BITMAP(bitmap, VirtIOMEM, 0, bitmap_size),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_virtio_mem = {
    .name = "virtio-mem",
    .minimum_version_id = 1,
    .version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
};

static void virtio_mem_fill_device_info(const VirtIOMEM *vmem,
                                        VirtioMEMDeviceInfo *vi)
{
    vi->memaddr = vmem->addr;
    vi->node = vmem->node;
    vi->requested_size = vmem->requested_size;
    vi->size = vmem->size;
    vi->max_size = memory_region_size(&vmem->memdev->mr);
    vi->block_size = vmem->block_size;
    vi->memdev = object_get_canonical_path(OBJECT(vmem->memdev));
}

static MemoryRegion *virtio_mem_get_memory_region(VirtIOMEM *vmem, Error **errp)
{
    if (!vmem->memdev) {
        error_setg(errp, "'%s' property must be set", VIRTIO_MEM_MEMDEV_PROP);
        return NULL;
    }

    return &vmem->memdev->mr;
}

static void virtio_mem_get_size(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    const VirtIOMEM *vm = VIRTIO_MEM(obj);
    uint64_t value = vm->size;

    visit_type_size(v, name, &value, errp);
}

static void virtio_mem_get_requested_size(Object *obj, Visitor *v,
                                          const char *name, void *opaque,
                                          Error **errp)
{
    const VirtIOMEM *vm = VIRTIO_MEM(obj);
    uint64_t value = vm->requested_size;

    visit_type_size(v, name, &value, errp);
}

static void virtio_mem_set_requested_size(Object *obj, Visitor *v,
                                          const char *name, void *opaque,
                                          Error **errp)
{
    VirtIOMEM *vm = VIRTIO_MEM(obj);
    Error *local_err = NULL;
    uint64_t value;

    visit_type_size(v, name, &value, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    /* Growing the usable region might later not be possible, disallow it. */
    if (virtio_mem_busy() && value > vm->requested_size) {
        error_setg(errp, "'%s' cannot be increased while migrating,"
                   " while dumping, or when certain vfio devices are used.",
                   name);
        return;
    }

    /*
     * The block size and memory backend are not fixed until the device was
     * realized. realize() will verify these properties then.
     */
    if (DEVICE(obj)->realized) {
        if (!QEMU_IS_ALIGNED(value, vm->block_size)) {
            error_setg(errp, "'%s' has to be multiples of '%s' (0x%" PRIx32
                       ")", name, VIRTIO_MEM_BLOCK_SIZE_PROP,
                       vm->block_size);
            return;
        } else if (value > memory_region_size(&vm->memdev->mr)) {
            error_setg(errp, "'%s' cannot exceed the memory backend size"
                       "(0x%" PRIx64 ")", name,
                       memory_region_size(&vm->memdev->mr));
            return;
        }

        if (value != vm->requested_size) {
            uint64_t tmp_size;

            vm->requested_size = value;

            /* Grow the usable region if required */
            tmp_size = MIN(memory_region_size(&vm->memdev->mr),
                           vm->requested_size + VIRTIO_MEM_USABLE_EXTENT);
            vm->usable_region_size = MAX(vm->usable_region_size, tmp_size);
        }
        /*
         * Trigger a config update so the guest gets notified. We trigger
         * even if the size didn't change (especially helpful for debugging).
         */
        virtio_notify_config(VIRTIO_DEVICE(vm));
    } else {
        vm->requested_size = value;
    }
}

static void virtio_mem_get_block_size(Object *obj, Visitor *v, const char *name,
                                      void *opaque, Error **errp)
{
    const VirtIOMEM *vm = VIRTIO_MEM(obj);
    uint64_t value = vm->block_size;

    visit_type_size(v, name, &value, errp);
}

static void virtio_mem_set_block_size(Object *obj, Visitor *v, const char *name,
                                      void *opaque, Error **errp)
{
    VirtIOMEM *vm = VIRTIO_MEM(obj);
    Error *local_err = NULL;
    uint64_t value;

    if (DEVICE(obj)->realized) {
        error_setg(errp, "'%s' cannot be changed", name);
        return;
    }

    visit_type_size(v, name, &value, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    if (value > UINT32_MAX) {
        error_setg(errp, "'%s' has to be smaller than 0x%" PRIx32, name,
                   UINT32_MAX);
        return;
    } else if (value < VIRTIO_MEM_MIN_BLOCK_SIZE) {
        error_setg(errp, "'%s' has to be at least 0x%" PRIx32, name,
                   VIRTIO_MEM_MIN_BLOCK_SIZE);
        return;
    } else if (!is_power_of_2(value)) {
        error_setg(errp, "'%s' has to be a power of two", name);
        return;
    }
    vm->block_size = value;
}

static void virtio_mem_instance_init(Object *obj)
{
    VirtIOMEM *vm = VIRTIO_MEM(obj);

    vm->block_size = VIRTIO_MEM_DEFAULT_BLOCK_SIZE;

    object_property_add(obj, VIRTIO_MEM_SIZE_PROP, "size", virtio_mem_get_size,
                        NULL, NULL, NULL, &error_abort);
    object_property_add(obj, VIRTIO_MEM_REQUESTED_SIZE_PROP, "size",
                        virtio_mem_get_requested_size,
                        virtio_mem_set_requested_size, NULL, NULL,
                        &error_abort);
    object_property_add(obj, VIRTIO_MEM_BLOCK_SIZE_PROP, "size",
                        virtio_mem_get_block_size, virtio_mem_set_block_size,
                        NULL, NULL, &error_abort);
}

static Property virtio_mem_properties[] = {
    DEFINE_PROP_UINT64(VIRTIO_MEM_ADDR_PROP, VirtIOMEM, addr, 0),
    DEFINE_PROP_UINT32(VIRTIO_MEM_NODE_PROP, VirtIOMEM, node, 0),
    DEFINE_PROP_LINK(VIRTIO_MEM_MEMDEV_PROP, VirtIOMEM, memdev,
                     TYPE_MEMORY_BACKEND, HostMemoryBackend *),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_mem_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);
    VirtIOMEMClass *vmc = VIRTIO_MEM_CLASS(klass);

    dc->props = virtio_mem_properties;
    dc->vmsd = &vmstate_virtio_mem;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    vdc->realize = virtio_mem_device_realize;
    vdc->unrealize = virtio_mem_device_unrealize;
    vdc->get_config = virtio_mem_get_config;
    vdc->get_features = virtio_mem_get_features;
    vdc->vmsd = &vmstate_virtio_mem_device;

    vmc->fill_device_info = virtio_mem_fill_device_info;
    vmc->get_memory_region = virtio_mem_get_memory_region;
}

static const TypeInfo virtio_mem_info = {
    .name = TYPE_VIRTIO_MEM,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOMEM),
    .instance_init = virtio_mem_instance_init,
    .class_init = virtio_mem_class_init,
    .class_size = sizeof(VirtIOMEMClass),
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_mem_info);
}

type_init(virtio_register_types)
