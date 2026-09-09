#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

KSYMTAB_FUNC(sysentinel_mei_send, "");
SYMBOL_FLAGS(sysentinel_mei_send, 0x01);
KSYMTAB_FUNC(sysentinel_mei_recv, "");
SYMBOL_FLAGS(sysentinel_mei_recv, 0x01);

MODULE_INFO(depends, "mei");

