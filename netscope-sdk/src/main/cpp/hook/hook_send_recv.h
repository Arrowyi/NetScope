#pragma once
namespace netscope {
int  install_hook_send_recv(); // 0 on success, non-zero = count of failed sub-hooks
void verify_hook_send_recv();
void uninstall_hook_send_recv();
} // namespace netscope
