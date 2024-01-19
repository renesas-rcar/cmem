/*************************************************************************/ /*
 Memory Driver (kernel module)

 Copyright (C) 2015 - 2017 Renesas Electronics Corporation

 License        Dual MIT/GPLv2

 The contents of this file are subject to the MIT license as set out below.

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 Alternatively, the contents of this file may be used under the terms of
 the GNU General Public License Version 2 ("GPL") in which case the provisions
 of GPL are applicable instead of those above.

 If you wish to allow use of your version of this file only under the terms of
 GPL, and not to allow others to use your version of this file under the terms
 of the MIT license, indicate your decision by deleting the provisions above
 and replace them with the notice and other provisions required by GPL as set
 out in the file called "GPL-COPYING" included in this distribution. If you do
 not delete the provisions above, a recipient may use your version of this file
 under the terms of either the MIT license or GPL.

 This License is also included in this distribution in the file called
 "MIT-COPYING".

 EXCEPT AS OTHERWISE STATED IN A NEGOTIATED AGREEMENT: (A) THE SOFTWARE IS
 PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 PURPOSE AND NONINFRINGEMENT; AND (B) IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 GPLv2:
 If you wish to use this file under the terms of GPL, following terms are
 effective.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/ /*************************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/of_device.h>
#include <linux/types.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>

#include "cmemdrv.h"

#define MAX_AREA_NUM 42
#define DEFAULT_AREA_SIZE (16 * 1024 * 1024)

struct mem_area_data {
	struct device *dev;
	size_t size;
	void *virt_ptr;
	int prop;
	dma_addr_t phys_addr;
};

struct mem_access_data {
	struct mem_area_data* area;
	int start_offset;
	int offset;
	int width;
	int height;
	int stride;
	int locked;
	int tl;
};

struct cmem_other_device {
    int major;
    struct list_head list;
};

static LIST_HEAD(device_list);

static unsigned int bsize_count;
static unsigned long bsize[MAX_AREA_NUM];
module_param_array(bsize, ulong, &bsize_count, S_IRUGO);
static int cached = 1;
module_param(cached, int, S_IRUGO);

#ifdef CFG_USE_FPGA
static unsigned long cfg_bsize = 0;
module_param(cfg_bsize, ulong, S_IRUGO);
#endif

static unsigned int cmem_major = 288;		// 0:auto
module_param(cmem_major, uint, S_IRUGO);

static bool no_map_skip; // checking for no-map regions
static bool bit_ranges; // checking for 40-bit regions
const char *label;  // checking for node name

static struct class *cmem_class = NULL;
static struct mem_area_data *cmem_areas[MAX_AREA_NUM];

static int cv_v_to_p(unsigned long vaddr, unsigned long *paddr)
{
	struct vm_area_struct *vma;
	unsigned long start, offset;
	unsigned long pfn;
	int ret;

	*paddr = 0;

	vma = find_vma(current->active_mm, vaddr);
	if (vma == NULL)
		return -EINVAL;

	start = vaddr & PAGE_MASK;
	ret = follow_pfn(vma, start, &pfn);
	if (ret < 0)
		return ret;

	offset = offset_in_page(vaddr);
	*paddr = (pfn << PAGE_SHIFT) + offset;

	return 0;
}

static void do_tl(u64 *src, u64 *dst, unsigned int height, unsigned int step)
{
	unsigned int i;
	int j;
	unsigned int yaddr;
	u64 *isrc, *idst, *isrcp, *idstp;

	for (j = 0; j < height ; j += 2) {
		yaddr = (j & ~0x1f) * step | ((j & 0x1f) << 7);
		isrc = src + (yaddr >> 3);
		idst = dst + (j * step >> 3);
		for (i = 0; i < step >> 3; i += 16) {
			idstp = idst + i;
			isrcp = isrc + (i << 5);
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;

			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;

			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;

			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;

			idstp = idst + i + (step >> 3);
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;

			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;

			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;

			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;
			*idstp++ = *isrcp++;

			//idst[i] = isrc[((i >> 4) << 9) + (i & 0xf)];
		}
	}
}

static ssize_t dev_read(struct file *filep, char *buf, size_t len, loff_t *ppos)
{
	size_t count;
	struct mem_access_data *p = filep->private_data;

	if (p->tl) {
		do_tl( (u64 *)(p->area->virt_ptr + p->offset + p->start_offset),
		       (u64 *)buf, p->height, p->stride );
		count = len;
	} else {
		count = copy_to_user(buf, p->area->virt_ptr + p->offset + p->start_offset, len);
	}

	return count;
}

static ssize_t dev_write(struct file *filep, const char *buf, size_t len, loff_t *ppos)
{
	size_t count;
	struct mem_access_data *p = filep->private_data;

	count = copy_from_user(p->area->virt_ptr + p->offset + p->start_offset, buf, len);

	return count;
}

static long dev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct mem_access_data *p = filep->private_data;
	struct device *dev = p->area->dev;
	struct mem_mlock mlock;
	struct mem_setpara setpara;
	struct mem_info minfo;
	int ret = 0;
	switch (cmd) {
	case PARAM_SET :
		ret = copy_from_user(&setpara,  (struct mem_setpara *)arg, sizeof(setpara));
		p->width = setpara.width;
		p->height = setpara.height;
		p->stride = setpara.stride;
		p->tl = setpara.tl;
		p->offset = setpara.offset;
		break;
	case M_ALLOCATE :
		break;
	case M_LOCK :
		if (cached && !p->area->prop) {
			ret = copy_from_user(&mlock, (struct mem_mlock *)arg, sizeof(mlock));

			if (mlock.dir == IOCTL_FROM_DEV_TO_CPU)
				dma_sync_single_for_device(dev, p->area->phys_addr + p->start_offset +
							   mlock.offset, mlock.size, DMA_FROM_DEVICE);
			else
				dma_sync_single_for_device(dev, p->area->phys_addr + p->start_offset +
							   mlock.offset, mlock.size, DMA_TO_DEVICE);
		} else {
			dev_warn(dev, "## Operation not permitted with this region\n");
			return -EPERM;
		}
		break;
	case M_UNLOCK :
		if (cached && !p->area->prop) {
			ret = copy_from_user(&mlock, (struct mem_mlock *)arg, sizeof(mlock));

			if (mlock.dir == IOCTL_FROM_DEV_TO_CPU)
				dma_sync_single_for_cpu(dev, p->area->phys_addr + p->start_offset +
							mlock.offset, mlock.size, DMA_FROM_DEVICE);
			else
				dma_sync_single_for_cpu(dev, p->area->phys_addr + p->start_offset +
							mlock.offset, mlock.size, DMA_TO_DEVICE);
		} else {
			dev_warn(dev, "## Operation not permitted with this region\n");
			return -EPERM;
		}
		break;
	case M_UNALLOCATE :
		break;
	case GET_PHYS_ADDR :
		minfo.phys_addr = (size_t)p->area->phys_addr;
		ret = copy_to_user((struct mem_info *)arg, &minfo, sizeof(minfo));
		break;
	case TRY_CONV :
		cv_v_to_p( ( (unsigned long *)arg )[0], (unsigned long *)arg + 1);
		break;
	default:
		dev_warn(dev, "## unknown ioctl command %d\n", cmd);
		return -EINVAL;
	}

	return ret;
}

static int dev_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct mem_access_data *p = filep->private_data;
	unsigned long off;
	unsigned long start;

	if (vma->vm_pgoff > (~0UL >> PAGE_SHIFT))
		return -EINVAL;

	off = vma->vm_pgoff << PAGE_SHIFT;
	start = p->area->phys_addr;

	if ((vma->vm_end - (vma->vm_start + off)) > p->area->size)
		return -EINVAL;

	off += start;
	vma->vm_pgoff = off >> PAGE_SHIFT;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	if (!cached)
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range( vma,
	                        vma->vm_start,
	                        vma->vm_pgoff,
	                        vma->vm_end - vma->vm_start,
	                        vma->vm_page_prot ) ;
}

static int dev_open(struct inode *inode, struct file *filep)
{
	struct mem_access_data *mem_access_p;
	int minor = iminor(inode);
	struct mem_area_data* area = cmem_areas[minor];

	mem_access_p = kzalloc(sizeof(*mem_access_p), GFP_KERNEL);
	if (!mem_access_p)
		return -ENOMEM;

	dev_dbg(area->dev, "Device Open\n");
	mem_access_p->area = area;
	filep->private_data = mem_access_p;

	return 0;
}

static int dev_rls(struct inode *inode, struct file *filep)
{
	struct mem_access_data *mem_access_p = filep->private_data;
	kfree(mem_access_p);
	return 0;
}

static struct file_operations fops = {
	.owner          = THIS_MODULE,
	.read           = dev_read,
	.write          = dev_write,
	.unlocked_ioctl = dev_ioctl,
	.compat_ioctl   = dev_ioctl,
	.mmap           = dev_mmap,
	.open           = dev_open,
	.release        = dev_rls,
};

static int parse_reserved_mem_dt(struct device_node *np,
				 u64 *reserved_size, int index)
{
	const __be32 *regaddr_p = NULL, *find;
	struct device_node *node = NULL;
	struct resource r;
	resource_size_t base_size;
	int ret = 0;

	node = of_parse_phandle(np, "memory-region", index);
	if (node) {
		/* Getting the size of the reverved memory region */
		regaddr_p = of_get_address(node, 0, reserved_size, NULL);

		if (regaddr_p) {
			of_translate_address(node, regaddr_p);
		} else {
			pr_err("No reserved memory node for CMEM was found\n");
			ret = -1;
		}

		/* Identify as if the region is configured as no-map */
		no_map_skip = false;
		find = of_get_property(node, "no-map", NULL);
		if (find)
			no_map_skip = true;

		/* Identify as if the region is 40-bit or 32-bit */
		of_address_to_resource(node, 0, &r);
		base_size = r.end;

		if (base_size <= 0xFFFFFFFF) { // 32-bit
			bit_ranges = false;
		} else if (base_size > 0xFFFFFFFF && base_size <= 0xFFFFFFFFFF) { // 40-bit
			bit_ranges = true;
		} else {
			pr_err("This region is over 40-bit\n");
			bit_ranges = false;
		}

		/* Node name for naming cmem_other devices */
		label = node->name;

	} else {
		pr_err("Unable to parse 'memory-region'\n");
	}

	of_node_put(node);

	return ret;
}

static int cmemdrv_create_device(dev_t devt, size_t size)
{
	int ret;
	struct mem_area_data *area;
	struct device *dev;
	void *virt_b_ptr;
	dma_addr_t phy_b_addr;

	dev = device_create(cmem_class, NULL, devt, NULL, "cmem%d", MINOR(devt));
	if (IS_ERR(dev)) {
		pr_err("cmem: unable to create device cmem%d\n", MINOR(devt));
		return PTR_ERR(dev);
	}

	area = devm_kzalloc(dev, sizeof(*area), GFP_KERNEL);
	if (!area) {
		ret = -ENOMEM;
		goto err;
	}
	area->dev = dev;

	dev->coherent_dma_mask = DMA_BIT_MASK(32);
#ifdef CONFIG_ARM64
	{
		struct device_node *np;
		np = of_find_compatible_node(NULL, NULL, "shared-dma-pool");
		of_dma_configure(dev, np, true);
	}
#endif

	virt_b_ptr = dmam_alloc_coherent(dev, size + PAGE_SIZE, &phy_b_addr, GFP_KERNEL);
	if (!virt_b_ptr) {
		dev_err(dev, "Memory allocation failed.. (size:0x%zx)\n", size);
		ret = -ENOMEM;
		goto err;
	}

	area->virt_ptr = PTR_ALIGN(virt_b_ptr, PAGE_SIZE);
	area->phys_addr = phy_b_addr + (area->virt_ptr - virt_b_ptr);
	area->size = size;
	cmem_areas[MINOR(devt)] = area;
	dev_notice(dev, "Memory allocated.. 0x%08lx (size:0x%zx)\n", (unsigned long)area->phys_addr, size);

	return 0;

err:
	device_destroy(cmem_class, devt);
	return ret;
}

static int cmemdrv_create_device_other_region(dev_t devt, int index,
					      u64 reserved_size,
						  struct device_node *np)
{
	struct mem_area_data *area;
	struct device *dev;
	void *virt_b_ptr;
	int ret = 0;
	const char *node_name;
	dma_addr_t phy_b_addr;

	if (*label == 0x00) {
		pr_info("cmem: Node name not found; assigning device name with a number\n");
		dev = device_create(cmem_class, NULL, devt, NULL, "cmem_other%d", index);
	} else {
		node_name = label;

		label = strchr(label, ',');
		if (label != NULL)
			node_name = label + 1;

		dev = device_create(cmem_class, NULL, devt, NULL, "cmem_%s", node_name);
	}

	if (IS_ERR(dev)) {
		pr_err("cmem: Unable to create device cmem_%s or cmem_other%d\n", node_name, index);
		return PTR_ERR(dev);
	}

	area = devm_kzalloc(dev, sizeof(*area), GFP_KERNEL);
	if (!area) {
		ret = -ENOMEM;
		goto err;
	}
	area->dev = dev;

	if (bit_ranges) {
		dev->coherent_dma_mask = DMA_BIT_MASK(40);
	} else {
		dev->coherent_dma_mask = DMA_BIT_MASK(32);
	}

	of_dma_configure(dev, np, true);

	ret = of_reserved_mem_device_init_by_idx(area->dev, np, index);
	if (ret) {
		dev_err(dev, "Unable to get the reserved memory\n");
		goto err;
	}

	virt_b_ptr = dmam_alloc_coherent(dev, reserved_size,
					 &phy_b_addr, GFP_KERNEL);

	if (!virt_b_ptr) {
		dev_err(dev, "Memory allocation failed.. (size:0x%llx)\n", reserved_size);
		ret = -ENOMEM;
		goto err;
	}

	area->virt_ptr = PTR_ALIGN(virt_b_ptr, PAGE_SIZE);
	area->phys_addr = phy_b_addr + (area->virt_ptr - virt_b_ptr);
	area->size = reserved_size;
	area->prop = no_map_skip;
	cmem_areas[MINOR(devt)] = area;
	dev_notice(dev, "Memory allocated.. 0x%08lx (size:0x%lx) [%ld MiB]\n",
		   (unsigned long)area->phys_addr,
		   (unsigned long)area->size,
		   (unsigned long)area->size / SZ_1M);
	return 0;

err:
	device_destroy(cmem_class, devt);
	return ret;
}

static int cmem_other_register_device(void)
{
	struct cmem_other_device *othr_dev;

	othr_dev = kmalloc(sizeof(*othr_dev), GFP_KERNEL);
	if (!othr_dev) {
		pr_err("Failed to allocate memory for the device\n");
		return -ENOMEM;
	}

	othr_dev->major = register_chrdev(0, "CMem-Other", &fops);
	if (othr_dev->major < 0) {
		printk(KERN_ALERT "Failed to register major number\n");
		kfree(othr_dev);
		return othr_dev->major;
	}

	INIT_LIST_HEAD(&othr_dev->list);
	list_add(&othr_dev->list, &device_list);

	return othr_dev->major;
}

static void cmem_other_unregister_devices(void)
{
    struct cmem_other_device *entry, *next;

	list_for_each_entry_safe(entry, next, &device_list, list) {
		device_destroy(cmem_class, MKDEV(entry->major, 0));
		unregister_chrdev(entry->major, "CMem-Other");
		list_del(&entry->list);
		kfree(entry);
    }
}

static int __init cmemdrv_init(void)
{
	int i = 0, prop_size = 0, index = 0;
	struct device_node *np;
	u64 reserved_size;
	int ret;

	if (bsize_count == 0)
		bsize[bsize_count++] = DEFAULT_AREA_SIZE;	/* add default area */

#ifdef CFG_USE_FPGA
	if (cfg_bsize && bsize_count < MAX_AREA_NUM)
		bsize[bsize_count++] = cfg_bsize;	/* for compatibility */
#endif

	ret = register_chrdev(cmem_major, "CMem", &fops);
	if (ret < 0) {
		pr_err("cmem: unable to get major %d\n", cmem_major);
		return ret;
	}
	if (cmem_major == 0)
		cmem_major = ret;

	cmem_class = class_create(THIS_MODULE, "cmem");
	if (IS_ERR(cmem_class)) {
		pr_err("cmem: unable to create class\n");
		ret = PTR_ERR(cmem_class);
		goto err1;
	}

	for (i = 0; i < bsize_count; i++) {
		ret = cmemdrv_create_device(MKDEV(cmem_major, i), bsize[i]);
		if (ret < 0)
			goto err2;
	}

	/* Looking for CMEM reserved memory */
	np = of_find_node_by_path("/cmem");
	of_get_property(np, "memory-region", &prop_size);
	if (prop_size) {
		/* Create devices that support other reserved memory regions */
		for (ret = 0; prop_size > 0; prop_size -= 4) {
			/* Devices registration */
			ret = cmem_other_register_device();
			if (ret < 0) {
				pr_err("cmem: unable to register device %d\n", ret);
				cmem_other_unregister_devices();
				return ret;
			}

			/* Parsing reserved memory size from DT */
			parse_reserved_mem_dt(np, &reserved_size, index);

			cmemdrv_create_device_other_region(MKDEV(ret, 0),
								 index, reserved_size, np);

			/* Ignore failed region, continue with the next region */
			index++;
		}
	}

	of_node_put(np);

	return 0;

err2:
	for (i--; i >= 0; i--)
		device_destroy(cmem_class, MKDEV(cmem_major, i));

	class_destroy(cmem_class);
err1:
	unregister_chrdev(cmem_major, "CMem");
	return ret;
}

static void __exit cmemdrv_exit(void)
{
	int i;

	for (i = 0; i < bsize_count; i++)
		device_destroy(cmem_class, MKDEV(cmem_major, i));

	unregister_chrdev(cmem_major, "CMem");
	cmem_other_unregister_devices();
	class_destroy(cmem_class);
}

module_init(cmemdrv_init)
module_exit(cmemdrv_exit)

MODULE_AUTHOR("RenesasElectronicsCorp.");
MODULE_DESCRIPTION("Userspace I/O driver for image memory");
MODULE_LICENSE("GPL v2");
