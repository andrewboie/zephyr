Memory Management Design Goals
##############################

- The core kernel will manage the virtual address space.

  - At boot, mappings are provided for the linked Zephyr image.
  - The total size of the virtual address space is specified at build time.
    The architecture is expected to pre-allocate paging structures such that
    any address range may be mapped within the bounds of the address space,
    without requring memory allocations for paging structures.
  - Zephyr provides functions for creating new memory mappings.

- The core kernel will manage physical memory pages composing main system RAM.
  The kernel will keep track of unused physical memory in order to satisfy
  memory page-ins and anonymous memory mappings. The core kernel does not
  manage ancillary memory regions such as DTCM.

- The core kernel does not maintain a detailed ontology of past memory mappings,
  except to manage free regions in the virtual address space.
  The current state of memory mappings is solely maintained at the
  architecture layer, via the configuration of page tables or whatever data
  structures are needed to implement the memory management policy.

- Use-cases that require buffers of contiguous physical memory should declare
  such buffers at build time. Buffers declared at build time and marked as
  pinned in memory are guaranteed to be physically contiguous.


Userspace Interactions
######################

The kernel has a single view of the address space at all times with respect
to supervisor mode. It is required that if multiple sets of page tables are in
use to implement memory domains, that virtual-to-physical mappings are
managed identically among all of them.

What may differ among page tables:

 - Accessed and dirty states for data pages
 - Permission settings, to implement individual memory domain access policy
   for partitions within the domain
 - Considerations for certain features like KPTI, but even in this case the
   virtual-to-physical mapping equivalence for all page tables should still be
   able to be derived

Functions like ``arch_page_location_get()`` which query only the current
set of page tables must return the same information regardless of which
set of page tables are in use.
