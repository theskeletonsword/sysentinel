savedcmd_sysentinel_core.o := OBJTREE=/usr/src/kernels/7.1.8-200.fc44.x86_64 RUST_MODFILE=./sysentinel_metrics /usr/bin/rustc --edition=2021 -Zbinary_dep_depinfo=y -Astable_features -Aunused_features -Dnon_ascii_idents -Dunsafe_op_in_unsafe_fn -Wmissing_docs -Wrust_2018_idioms -Wunreachable_pub -Wclippy::all -Wclippy::as_ptr_cast_mut -Wclippy::as_underscore -Wclippy::cast_lossless -Aclippy::collapsible_if -Aclippy::collapsible_match -Wclippy::ignored_unit_patterns -Aclippy::incompatible_msrv -Wclippy::mut_mut -Wclippy::needless_bitwise_bool -Aclippy::needless_lifetimes -Wclippy::no_mangle_with_rust_abi -Wclippy::ptr_as_ptr -Wclippy::ptr_cast_constness -Wclippy::ref_as_ptr -Wclippy::undocumented_unsafe_blocks -Aclippy::uninlined_format_args -Wclippy::unnecessary_safety_comment -Wclippy::unnecessary_safety_doc -Aclippy::unwrap_or_default -Wrustdoc::missing_crate_level_docs -Wrustdoc::unescaped_backticks -Cpanic=abort -Cembed-bitcode=n -Clto=n -Cforce-unwind-tables=n -Ccodegen-units=1 -Csymbol-mangling-version=v0 -Crelocation-model=static -Zfunction-sections=n -Wclippy::float_arithmetic --target=/usr/src/kernels/7.1.8-200.fc44.x86_64/scripts/target.json -Ctarget-feature=-sse,-sse2,-sse3,-ssse3,-sse4.1,-sse4.2,-avx,-avx2 -Zcf-protection=branch -Cjump-tables=n -Ctarget-cpu=x86-64 -Ztune-cpu=generic -Cno-redzone=y -Ccode-model=kernel -Zfunction-return=thunk-extern -Zpatchable-function-entry=16,16 -Copt-level=2 -Cdebug-assertions=n -Coverflow-checks=y -Cdebuginfo=2 --cfg mei_available  --cfg MODULE  @/usr/src/kernels/7.1.8-200.fc44.x86_64/include/generated/rustc_cfg -Zallow-features=arbitrary_self_types,asm_goto,generic_arg_infer,used_with_arg -Zcrate-attr=no_std -Zcrate-attr='feature(arbitrary_self_types,asm_goto,generic_arg_infer,used_with_arg)' -Zunstable-options --extern pin_init --extern kernel --crate-type rlib -L /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/ --sysroot=/dev/null --out-dir ./ --emit=dep-info=./.sysentinel_core.o.d --emit=obj=sysentinel_core.o sysentinel_core.rs  

source_sysentinel_core.o := sysentinel_core.rs

deps_sysentinel_core.o := \
    $(wildcard include/config/RUST) \
  hypercall.rs \
  psp.rs \
  mei_driver.rs \
    $(wildcard include/config/INTEL_MEI) \
  /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/libcore.rmeta \
  /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/libkernel.rmeta \
  /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/libffi.rmeta \
  /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/libcompiler_builtins.rmeta \
  /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/libpin_init.rmeta \
  /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/libpin_init_internal.so \
  /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/libmacros.so \
  /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/libbuild_error.rmeta \
  /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/libbindings.rmeta \
  /usr/src/kernels/7.1.8-200.fc44.x86_64/rust/libuapi.rmeta \

sysentinel_core.o: $(deps_sysentinel_core.o)

$(deps_sysentinel_core.o):
