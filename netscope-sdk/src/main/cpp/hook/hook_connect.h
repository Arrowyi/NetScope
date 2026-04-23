#pragma once
namespace netscope {
int  install_hook_connect();   // 0 on success, non-zero on failure
void verify_hook_connect();
void uninstall_hook_connect();
} // namespace netscope
