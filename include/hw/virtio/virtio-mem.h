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

#ifndef HW_VIRTIO_MEM_H
#define HW_VIRTIO_MEM_H

#include "standard-headers/linux/virtio_mem.h"
#include "hw/virtio/virtio.h"
#include "qapi/qapi-types-misc.h"
#include "sysemu/hostmem.h"

#define TYPE_VIRTIO_MEM "virtio-mem"

#define VIRTIO_MEM(obj) \
        OBJECT_CHECK(VirtIOMEM, (obj), TYPE_VIRTIO_MEM)
#define VIRTIO_MEM_CLASS(oc) \
        OBJECT_CLASS_CHECK(VirtIOMEMClass, (oc), TYPE_VIRTIO_MEM)
#define VIRTIO_MEM_GET_CLASS(obj) \
        OBJECT_GET_CLASS(VirtIOMEMClass, (obj), TYPE_VIRTIO_MEM)

#define VIRTIO_MEM_MEMDEV_PROP "memdev"
#define VIRTIO_MEM_NODE_PROP "node"
#define VIRTIO_MEM_SIZE_PROP "size"
#define VIRTIO_MEM_REQUESTED_SIZE_PROP "requested-size"
#define VIRTIO_MEM_BLOCK_SIZE_PROP "block-size"
#define VIRTIO_MEM_ADDR_PROP "memaddr"

typedef struct VirtIOMEM {
    VirtIODevice parent_obj;

    /* guest -> host request queue */
    VirtQueue *vq;

    /* postcopy notifier */
    NotifierWithReturn postcopy_notifier;

    /* bitmap used to track unplugged memory */
    int32_t bitmap_size;
    unsigned long *bitmap;

    /* assigned memory backend and memory region */
    HostMemoryBackend *memdev;

    /* NUMA node */
    uint32_t node;

    /* assigned address of the region in guest physical memory */
    uint64_t addr;
    uint64_t migration_addr;

    /* usable region size (<= region_size) */
    uint64_t usable_region_size;

    /* actual size (how much the guest plugged) */
    uint64_t size;

    /* requested size */
    uint64_t requested_size;

    /* block size and alignment */
    uint32_t block_size;
    uint32_t migration_block_size;
} VirtIOMEM;

typedef struct VirtIOMEMClass {
    /* private */
    VirtIODevice parent;

    /* public */
    void (*fill_device_info)(const VirtIOMEM *vmen, VirtioMEMDeviceInfo *vi);
    MemoryRegion *(*get_memory_region)(VirtIOMEM *vmem, Error **errp);
} VirtIOMEMClass;

#endif
