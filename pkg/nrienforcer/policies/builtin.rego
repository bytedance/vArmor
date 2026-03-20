package varmor.nri.builtin

import future.keywords.in

# 检查特权容器
# OCI Spec 中没有直接的 privileged 字段，所以这里只能采用近似判断
# 如果 spec.linux.maskedPaths 不存在或为空列表，且 capabilities 包含 SYS_ADMIN，通常是特权容器
is_privileged_container {
    not input.spec.linux.maskedPaths
    has_sys_admin_cap
}

has_sys_admin_cap {
    caps := input.spec.process.capabilities.effective
    some cap in caps
    cap == "SYS_ADMIN"
}

dangerous_caps_set = {"SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_PTRACE"}

# 检查危险 Capabilities
has_dangerous_capabilities {
    caps := input.spec.process.capabilities.effective
    some cap in caps
    cap in dangerous_caps_set
}

# 检查宿主机根目录挂载
mounts_host_root {
    some mount in input.spec.mounts
    mount.source == "/"
}

# 检查 Host Network 模式
# 在 OCI Spec 中，如果 linux.namespaces 列表中没有 type 为 "network" 的项
# 或者 path 指向宿主机命名空间 (通常为空或特定路径)，则为 Host Network
uses_host_network {
    # 获取所有 namespace types
    ns_types := {ns.type | ns := input.spec.linux.namespaces[_]}
    # 如果 "network" 不在 types 中，则是 Host Network
    not ns_types["network"]
}

# 检查 Host PID 模式
uses_host_pid {
    ns_types := {ns.type | ns := input.spec.linux.namespaces[_]}
    not ns_types["pid"]
}

# 检查资源限制 (CPU)
missing_cpu_limits {
    not has_cpu_limit
}

has_cpu_limit {
    quota := input.spec.linux.resources.cpu.quota
    quota > 0
}

# 检查资源限制 (Memory)
missing_memory_limits {
    not has_memory_limit
}

has_memory_limit {
    limit := input.spec.linux.resources.memory.limit
    limit > 0
}

# 检查镜像标签 (:latest)
has_latest_tag {
    endswith(input.image, ":latest")
}

# 检查镜像标签 (:edge)
has_edge_tag {
    endswith(input.image, ":edge")
}

# 检查是否以 Root 运行
runs_as_root {
    input.spec.process.user.uid == 0
}
