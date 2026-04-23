#pragma once
namespace netscope {
int  install_hook_close();     // 0 on success, non-zero on failure
void verify_hook_close();
void uninstall_hook_close();
} // namespace netscope
