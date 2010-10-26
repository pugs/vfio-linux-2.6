/*
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * uiommu driver - manipulation of iommu domains from user progs
 */
struct uiommu_domain {
	struct iommu_domain	*domain;
	atomic_t		refcnt;
};

/*
 * Kernel routines invoked by fellow driver (vfio)
 * after uiommu domain fd is passed in.
 */
struct uiommu_domain *uiommu_fdget(int fd);
void uiommu_put(struct uiommu_domain *);

/*
 * These inlines are placeholders for future routines
 * which may keep statistics, show info in sysfs, etc.
 */
static inline int uiommu_attach_device(struct uiommu_domain *udomain,
			       struct device *dev)
{
	return iommu_attach_device(udomain->domain, dev);
}

static inline void uiommu_detach_device(struct uiommu_domain *udomain,
				struct device *dev)
{
	iommu_detach_device(udomain->domain, dev);
}

static inline int uiommu_map(struct uiommu_domain *udomain,
				unsigned long iova,
				phys_addr_t paddr,
				int gfp_order,
				int prot)
{
	return iommu_map(udomain->domain, iova, paddr, gfp_order, prot);
}

static inline void uiommu_unmap(struct uiommu_domain *udomain,
					unsigned long iova,
					int gfp_order)
{
	iommu_unmap(udomain->domain, iova, gfp_order);
}

static inline phys_addr_t uiommu_iova_to_phys(struct uiommu_domain *udomain,
						unsigned long iova)
{
	return iommu_iova_to_phys(udomain->domain, iova);
}

static inline int uiommu_domain_has_cap(struct uiommu_domain *udomain,
						unsigned long cap)
{
	return iommu_domain_has_cap(udomain->domain, cap);
}
