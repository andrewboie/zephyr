/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef CONFIG_USERSPACE
	/*
         * The size of the gperf tables is both a function of the number of
	 * kernel objects, *and* the specific memory addresses being hashed.
	 * It is not something that can be predicted without actually building
	 * and compling it.
         */
	_kobject_data_area_start = .;
	*(".kobject_data.data*")
#if !defined(LINKER_PASS2) && defined(CONFIG_DYNAMIC_OBJECTS)
	PROVIDE(_thread_idx_map = .);
	. += CONFIG_MAX_THREAD_BYTES;
#endif
	_kobject_data_area_end = .;
	_kobject_data_area_used = ABSOLUTE(_kobject_data_area_end -
					   _kobject_data_area_start);



	/* In a valid build the MAX function will always evaluate to the
	 * second argument below, but to give the user a good error message
	 * when the area overflows we need to suppress the error that
	 * would be generated if the program counter would move backwards
	 * (which would be completely incomprehensible to the user what
	 * needed to be done) and perform an assertion instead which
	 * will at least point them in the right direction.
	 */
	_kobject_data_area_final = (_kobject_data_area_start +
				    CONFIG_KOBJECT_DATA_AREA);
	_kobject_data_area_wasted = ABSOLUTE(_kobject_data_area_final -
					     _kobject_data_area_end);
	. = MAX(., _kobject_data_area_final);

	ASSERT(ABSOLUTE(CONFIG_KOBJECT_DATA_AREA) >= _kobject_data_area_used,
	        "The configuration system has incorrectly set
		 'CONFIG_KOBJECT_DATA_AREA' to CONFIG_KOBJECT_DATA_AREA which
		 is not large enough. Please review the Kconfig documentation
		 for 'CONFIG_KOBJECT_DATA_AREA' to properly tune this value");
#endif /* CONFIG_USERSPACE */
