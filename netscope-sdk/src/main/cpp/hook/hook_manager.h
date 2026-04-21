#pragma once
namespace netscope {
int  hook_manager_init();    // returns 0 on success
void hook_manager_destroy();
void hook_manager_set_paused(bool paused);
bool hook_manager_is_paused();
} // namespace netscope
