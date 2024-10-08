# SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0

libcomposefs_dep = declare_dependency(link_with : libcomposefs, include_directories : config_inc)

thread_dep = dependency('threads')

executable('mkcomposefs',
    'mkcomposefs.c',
    dependencies : [libcomposefs_dep, thread_dep],
    link_with: [libcomposefs_internal],
    install : true,
)

executable('mount.composefs',
    'mountcomposefs.c',
    dependencies : [libcomposefs_dep],
    link_with: [libcomposefs_internal],
    install : true,
    install_dir : get_option('sbindir'),
)

executable('composefs-info',
    ['composefs-info.c', '../libcomposefs/hash.c'],
    c_args : composefs_hash_cflags,
    link_with: [libcomposefs_internal],
    dependencies : [libcomposefs_dep],
    install : true,
)

executable('composefs-dump',
    'composefs-dump.c',
    link_with: [libcomposefs_internal],
    dependencies : [libcomposefs_dep],
    install : false,
)

if fuse3_dep.found()
    executable('composefs-fuse',
        'cfs-fuse.c',
        dependencies : [libcomposefs_dep, fuse3_dep],
        install : false,
    )
endif
