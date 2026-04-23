#pragma once
namespace netscope {
int  install_hook_dns();       // 0 on success, non-zero on failure
void verify_hook_dns();
void uninstall_hook_dns();
} // namespace netscope
