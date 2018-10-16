project('nss_zerotier', 'cpp', version: '0.0.1', license: 'Unlicense',
	default_options: ['cpp_std=c++17', 'warning_level=2'])

cxx = meson.get_compiler('cpp')

conf_data = configuration_data()
if cxx.has_header_symbol('nsswitch.h', 'nss_module_unregister_fn')
	conf_data.set('HAS_BSD_NSS', true)
endif
conf_data.set_quoted('SOCKET_PATH', get_option('socket_path'))
conf_data.set_quoted('CONFIG_PATH_PREFIX', get_option('config_path_prefix'))
configure_file(output: 'config.hpp', configuration: conf_data)

thread_dep = dependency('threads')
curl_dep = dependency('libcurl')
rj_dep = dependency('RapidJSON')

here = include_directories('.')

ztnsd = executable('ztnsd', 'ztnsd.cpp',
	include_directories: [here],
	dependencies: [thread_dep, curl_dep, rj_dep],
	install: true)

zthost = executable('zthost', 'zthost.cpp',
	include_directories: [here],
	install: true)

libnss_zerotier = shared_library('nss_zerotier', 'nss_zerotier.cpp',
	include_directories: [here],
	cpp_args: ['-fno-exceptions', '-fno-rtti'],
	version: '1',
	name_prefix: '',
	install: true)
