/* SPDX-License-Identifier: Apache-2.0 */

#ifdef CONFIG_USERSPACE
	/* We need to reserve room for the gperf generated hash functions.
	 * Fortunately, unlike the data tables, the size of the code is
	 * reasonably predictable.
	 *
	 * The linker will error out complaining that the location pointer
	 * is moving backwards if the reserved room isn't large enough.
	 */
	_kobject_text_area_start = .;
	*(".kobject_data.text*")
	*(".kobject_data.rodata*")
	_kobject_text_area_end = .;
	_kobject_text_area_used = ABSOLUTE(_kobject_text_area_end -
					   _kobject_text_area_start);
#ifndef LINKER_PASS2
#ifdef CONFIG_DYNAMIC_OBJECTS
	PROVIDE(z_object_gperf_find = .);
	PROVIDE(z_object_gperf_wordlist_foreach = .);
#else
	PROVIDE(z_object_find = .);
	PROVIDE(z_object_wordlist_foreach = .);
#endif /* CONFIG_DYNAMIC_OBJECTS */
#endif /* LINKER_PASS2 */

	/* In a valid build the MAX function will always evaluate to the
	 * second argument below, but to give the user a good error message
	 * when the area overflows we need to suppress the error that
	 * would be generated if the program counter would move backwards
	 * (which would be completely incomprehensible to the user what
	 * needed to be done) and perform an assertion instead which
	 * will at least point them in the right direction.
	 */
	_kobject_text_area_final = (_kobject_text_area_start +
				    CONFIG_KOBJECT_TEXT_AREA);
	_kobject_text_area_wasted = ABSOLUTE(_kobject_text_area_final -
					     _kobject_text_area_end);
	. = MAX(., _kobject_text_area_final);

	ASSERT(CONFIG_KOBJECT_TEXT_AREA >= _kobject_text_area_used,
	        "The configuration system has incorrectly set
		 'CONFIG_KOBJECT_TEXT_AREA' to CONFIG_KOBJECT_TEXT_AREA which
		 is not large enough. Please review the Kconfig documentation
		 for 'CONFIG_KOBJECT_TEXT_AREA' to properly tune this value");
#endif /* CONFIG_USERSPACE */
