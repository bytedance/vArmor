import React, { useState, useEffect } from "react";
import YAML from "js-yaml";
import Layout from '@theme/Layout';
import clsx from 'clsx';
import styles from './policy-advisor.module.css';

// ---------------- Utility helpers ----------------
const hasCommonItem = (arr1 = [], arr2 = []) => {
  for (const item of arr1) {
    if (item === '*') return true;
    if (arr2.includes(item)) return true;
  }
  return false;
};

// NOTE: The following helpers depend on your ArmorProfileModel schema.
// Replace the dummy implementations with real extractors once you know
// the exact JSON structure.
const retrieveCapabilitiesFromModel = (model = {}) => {
  const caps = [];
  if (model.data && model.data.dynamicResult && model.data.dynamicResult.apparmor && model.data.dynamicResult.apparmor.capabilities) {
    caps.push(...model.data.dynamicResult.apparmor.capabilities);
  }
  return caps;
};

const retrieveSyscallsFromModel = (model = {}) => {
  if (model.data && model.data.dynamicResult && model.data.dynamicResult.seccomp && model.data.dynamicResult.seccomp.syscalls) {
    return model.data.dynamicResult.seccomp.syscalls;
  }
  return [];
};

const retrieveExecutionsFromModel = (model = {}) => {
  const executions = [];
  if (model.data && model.data.dynamicResult && model.data.dynamicResult.apparmor && model.data.dynamicResult.apparmor.executions) {
    for (const execution of model.data.dynamicResult.apparmor.executions) {
      executions.push(execution.split('/').pop());
    }
  }
  return executions;
};

const retrieveFilesFromModel = (model = {}) => {
  const files = [];
  if (model.data && model.data.dynamicResult && model.data.dynamicResult.apparmor && model.data.dynamicResult.apparmor.files) {
    files.push(...model.data.dynamicResult.apparmor.files);
  }
  return files;
};
const filesConflictWithRule = (ruleFiles = [], modelFiles = []) => {
  for (const file of modelFiles) {
    for (const rule of ruleFiles) {
      const path = file.oldPath || file.path;
      if (new RegExp(rule.path_regex).test(path) && 
          hasCommonItem(rule.permissions, file.permissions)) {
        return true;
      }
    }
  }
  return false;
};

// ---------------- Core filtering logic ----------------
const skipRuleWithContext = (rule, enforcers, appFeatures, appCapabilities) => {
  if (!hasCommonItem(enforcers, rule.enforcers)) return true;

  if (rule.conflicts) {
    const { features, capabilities } = rule.conflicts;
    if (features && hasCommonItem(features, appFeatures)) return true;
    if (capabilities && hasCommonItem(capabilities, appCapabilities)) return true;
  }

  if (rule.applicable) {
    const { features, capabilities } = rule.applicable;
    if (features && hasCommonItem(features, appFeatures)) return false;
    if (capabilities && hasCommonItem(capabilities, appCapabilities)) return false;
    return true;
  }

  return false;
};

const skipRuleWithModelData = (rule, enforcers, model = {}) => {
  if (!hasCommonItem(enforcers, rule.enforcers)) return true;
  if (!rule.conflicts) return false;

  const {
    capabilities: capConf,
    syscalls: scConf,
    executions: exConf,
    files: fConf,
  } = rule.conflicts;

  if (capConf) {
    const modelCaps = retrieveCapabilitiesFromModel(model);
    return hasCommonItem(capConf, modelCaps);
  }
  if (scConf) {
    const syscalls = retrieveSyscallsFromModel(model);
    return hasCommonItem(scConf, syscalls);
  }
  if (exConf) {
    const execs = retrieveExecutionsFromModel(model);
    return hasCommonItem(exConf, execs);
  }
  if (fConf) {
    const files = retrieveFilesFromModel(model);
    return filesConflictWithRule(fConf, files);
  }
  return false;
};

const setEnforcer = (policy, enforcers) => {
  if (!policy.enforcer.includes("AppArmor") && enforcers.includes("apparmor")){
    policy.enforcer += "AppArmor";
    policy.enhanceProtect.AppArmorRawRules=[]
  }
    
  if (!policy.enforcer.includes("BPF") && enforcers.includes("bpf")){
    policy.enforcer += "BPF";
    policy.enhanceProtect.BpfRawRules={}
  }
    
  if (!policy.enforcer.includes("Seccomp") && enforcers.includes("seccomp")){
    policy.enforcer += "Seccomp";
    policy.enhanceProtect.SyscallRawRules=[]
  }

};

const generatePolicy = (
  builtInRules,
  enforcers,
  appFeatures = [],
  appCapabilities = [],
  model = {}
) => {
  console.log(model);
	var policyAll = {
    apiVersion: "crd.varmor.org/v1beta1",
    kind: "VarmorPolicy",
    metadata: {
      name: "POLICY_NAME",
      namespace: "POLICY_NAMESPACE",
      labels: {},
      annotations: {}
    },
    spec: {
      updateExistingWorkloads: true,
      target: {
        kind: "",
        selector: {},
        name: "",
        containers: [],
      },
      policy: {},
    },
  };
  const policy = {
		enforcer: "",
		mode: "EnhanceProtect",
		enhanceProtect: {
      auditViolations: true,
      allowViolations: false,
			privileged: false,
			hardeningRules: [],
			attackProtectionRules: [
				{
					rules: [],
					targets: [],
				},
			],
			vulMitigationRules: [],
		},
	};

  const debugPrint = () => {};

  // privileged container flag
  if (appFeatures.includes("privileged-container")) {
    policy.enhanceProtect.privileged = true;
  }

  // ------------- escape_pattern -------------
  builtInRules.escape_pattern.forEach((rule) => {
    if (
      skipRuleWithContext(rule, enforcers, appFeatures, appCapabilities) ||
      skipRuleWithModelData(rule, enforcers, model)
    )
      return;
    setEnforcer(policy, enforcers);
    policy.enhanceProtect.hardeningRules.push(rule.id);
    debugPrint(rule);
  });

  // ------------- capability & capability_set -------------
  if (!hasCommonItem(["privileged-container", "dind"], appFeatures)) {
    let existCapRules = false;
    for (const rule of builtInRules.capability_set) {
      if (
        skipRuleWithContext(rule, enforcers, appFeatures, appCapabilities) ||
        skipRuleWithModelData(rule, enforcers, model)
      )
        continue;
      setEnforcer(policy, enforcers);
      policy.enhanceProtect.hardeningRules.push(rule.id);
      existCapRules = true;
      break;
    }

    if (!existCapRules) {
      builtInRules.capability.forEach((rule) => {
        if (
          skipRuleWithContext(rule, enforcers, appFeatures, appCapabilities) ||
          skipRuleWithModelData(rule, enforcers, model)
        )
          return;
        setEnforcer(policy, enforcers);
        policy.enhanceProtect.hardeningRules.push(rule.id);
      });
    }
  }

  // ------------- blocking_exploit_vectors -------------
  builtInRules.blocking_exploit_vectors.forEach((rule) => {
    if (
      skipRuleWithContext(rule, enforcers, appFeatures, appCapabilities) ||
      skipRuleWithModelData(rule, enforcers, model)
    )
      return;
    setEnforcer(policy, enforcers);
    policy.enhanceProtect.hardeningRules.push(rule.id);
  });

  // ------------- information_leak -------------
  builtInRules.information_leak.forEach((rule) => {
    if (
      skipRuleWithContext(rule, enforcers, appFeatures, appCapabilities) ||
      skipRuleWithModelData(rule, enforcers, model)
    )
      return;
    setEnforcer(policy, enforcers);
    policy.enhanceProtect.attackProtectionRules[0].rules.push(rule.id);
  });

  // ------------- sensitive_operations (only if model) -------------
  if (Object.keys(model).length) {
    builtInRules.sensitive_operations.forEach((rule) => {
      if (
        skipRuleWithContext(rule, enforcers, appFeatures, appCapabilities) ||
        skipRuleWithModelData(rule, enforcers, model)
      )
        return;
      setEnforcer(policy, enforcers);
      policy.enhanceProtect.attackProtectionRules[0].rules.push(rule.id);
    });
  }

  // ------------- vulnerability_mitigation -------------
  builtInRules.vulnerability_mitigation.forEach((rule) => {
    if (
      skipRuleWithContext(rule, enforcers, appFeatures, appCapabilities) ||
      skipRuleWithModelData(rule, enforcers, model)
    )
      return;
    setEnforcer(policy, enforcers);
    policy.enhanceProtect.vulMitigationRules.push(rule.id);
  });
  policyAll.spec.policy = policy;
  //console.log(policyAll);
  return policyAll;
};

// ---------------- React Component ----------------
export default function PolicyAdvisor() {
  // 步骤状态
  const [currentStep, setCurrentStep] = useState(1);
  const [builtInRules, setBuiltInRules] = useState(null);
  const [isCapabilitiesExpanded, setIsCapabilitiesExpanded] = useState(false);
  const [isPrivilegedExpanded, setIsPrivilegedExpanded] = useState(false);
  const [isContainerdExpanded, setIsContainerdExpanded] = useState(false);
  
  // 表单状态
  const [formData, setFormData] = useState({
    enforcers: [],
    features: [],
    capabilities: [],
  });
  
  const [behaviorModel, setBehaviorModel] = useState({});
  const [outputYAML, setOutputYAML] = useState("");
  
  // Tooltip状态
  const [tooltipContent, setTooltipContent] = useState("");
  const [tooltipVisible, setTooltipVisible] = useState(false);
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });
  
  // 显示tooltip
  const showTooltip = (content, e) => {
    setTooltipContent(content);
    setTooltipPosition({ x: e.clientX, y: e.clientY });
    setTooltipVisible(true);
  };
  
  // 隐藏tooltip
  const hideTooltip = () => {
    setTooltipVisible(false);
  };

  // 可用的强制访问控制器选项
  const enforcerOptions = [
    { value: 'apparmor', label: 'AppArmor' },
    { value: 'bpf', label: 'BPF' },
    { value: 'seccomp', label: 'Seccomp' }
  ];

  // 应用特性选项
  const featureOptions = [
    { value: 'privileged-container', label: '特权容器 - 目标应用在特权容器中运行' },
    { value: 'mount-sth', label: '挂载文件 - 目标应用需要在容器中执行文件挂载操作' },
    { value: 'umount-sth', label: '卸载文件 - 目标应用需要在容器中执行文件卸载操作' },
    { value: 'share-containers-pid-ns', label: '共享容器 PID 命名空间 - Pod 使用了 shareProcessNamespace:true 来共享容器的 PID 命名空间' },
    { value: 'share-host-pid-ns', label: '共享宿主机 PID 命名空间 - Pod 使用了 hostPID:true 来共享宿主机的 PID 命名空间' },
    { value: 'dind', label: 'Docker in Docker - 目标应用将在容器内创建 Docker in Docker 容器' },
    { value: 'require-sa', label: 'API Server 交互 - 目标应用明确需要与 API Server 交互' },
    { value: 'bind-privileged-socket-port', label: '监听特权端口 - 目标应用需要监听小于 1024 的网络端口' },
    { value: 'load-bpf', label: '加载 eBPF 程序 - 目标应用需要在容器中加载 eBPF 程序' }
  ];

  // 常用能力选项
  const capabilityOptions = [
    { value: 'sys_admin', label: 'SYS_ADMIN - 系统管理员权限' },
    { value: 'net_admin', label: 'NET_ADMIN - 网络管理员权限' },
    { value: 'sys_ptrace', label: 'SYS_PTRACE - 允许进程跟踪' },
    { value: 'sys_module', label: 'SYS_MODULE - 允许加载内核模块' },
    { value: 'dac_override', label: 'DAC_OVERRIDE - 覆盖文件访问限制' },
    { value: 'dac_read_search', label: 'DAC_READ_SEARCH - 绕过文件读取权限检查' },
    { value: 'kill', label: 'KILL - 允许发送信号给任何进程' },
    { value: 'bpf', label: 'BPF - 允许使用BPF系统调用' },
    { value: 'syslog', label: 'SYSLOG - 允许使用syslog系统调用' },
    { value: 'net_bind_service', label: 'NET_BIND_SERVICE - 允许绑定特权端口' },
    { value: 'net_raw', label: 'NET_RAW - 允许使用原始套接字' },
    { value: 'chown', label: 'CHOWN - 允许修改文件所有者' }
  ];

  useEffect(() => {
    // Load built-in rules once component mounts
    fetch("/built-in-rules.json")
      .then((res) => res.json())
      .then(setBuiltInRules)
      .catch((err) => console.error("Failed to load built-in rules", err));
  }, []);

  const [fileInputValue, setFileInputValue] = useState('');
  const [fileName, setFileName] = useState('');

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    setFileName(file ? file.name : '');
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const json = JSON.parse(evt.target.result);
        setBehaviorModel(json);
      } catch (err) {
        alert("Invalid JSON file");
      }
    };
    reader.readAsText(file);
  };

  // 处理强制访问控制器选择变更
  const handleEnforcerChange = (enforcer, checked) => {
    let updatedEnforcers = [...formData.enforcers];
    
    if (checked) {
      updatedEnforcers.push(enforcer);
    } else {
      updatedEnforcers = updatedEnforcers.filter(e => e !== enforcer);
    }
    
    setFormData({
      ...formData,
      enforcers: updatedEnforcers
    });
  };

  // 处理特性选择变更
  const handleFeatureChange = (feature, checked) => {
    let updatedFeatures = [...formData.features];
    
    if (checked) {
      updatedFeatures.push(feature);
    } else {
      updatedFeatures = updatedFeatures.filter(f => f !== feature);
    }
    
    setFormData({
      ...formData,
      features: updatedFeatures
    });
  };

  // 处理能力选择变更
  const handleCapabilityChange = (capability, checked) => {
    let updatedCapabilities = [...formData.capabilities];
    
    if (checked) {
      updatedCapabilities.push(capability);
    } else {
      updatedCapabilities = updatedCapabilities.filter(c => c !== capability);
    }
    
    setFormData({
      ...formData,
      capabilities: updatedCapabilities
    });
  };

  const handleGenerate = () => {
    if (!builtInRules) {
      alert("Built-in rules not loaded yet");
      return;
    }
    if (formData.enforcers.length === 0) {
      alert("请至少选择一个强制访问控制器");
      return;
    }

    const policy = generatePolicy(
      builtInRules, 
      formData.enforcers, 
      formData.features, 
      formData.capabilities, 
      behaviorModel
    );
    setOutputYAML(YAML.dump(policy));
    setCurrentStep(3); // 跳转到结果页面
  };

  // 渲染步骤导航
  const renderStepNav = () => {
    return (
      <div className={styles.stepNav}>
        <div className={clsx(styles.stepItem, currentStep >= 1 && styles.activeStep)} onClick={() => setCurrentStep(1)}>
          <div className={styles.stepNumber}>1</div>
          <div className={styles.stepLabel}>选择强制访问控制器</div>
        </div>
        <div className={clsx(styles.stepItem, currentStep >= 2 && styles.activeStep)} onClick={() => formData.enforcers.length > 0 && setCurrentStep(2)}>
          <div className={styles.stepNumber}>2</div>
          <div className={styles.stepLabel}>提供上下文信息</div>
        </div>
        <div className={clsx(styles.stepItem, currentStep >= 3 && styles.activeStep)} onClick={() => outputYAML && setCurrentStep(3)}>
          <div className={styles.stepNumber}>3</div>
          <div className={styles.stepLabel}>生成策略模板</div>
        </div>
      </div>
    );
  };

  // 渲染步骤1：选择强制访问控制器
  const renderStep1 = () => {
    return (
      <div className={styles.stepContent}>
        <h2>第一步：选择强制访问控制器</h2>
        <p>请选择目标环境支持的强制访问控制器。</p>
        <p>vArmor 将 AppArmor LSM、BPF LSM、Seccomp 抽象为了强制访问控制器（即 Enforcer），安全策略可以单独或组合使用它们来加固工作负载。</p>
        
        <div className={styles.formGroup}>
          <div className={styles.checkboxGroup}>
            {enforcerOptions.map(option => {
              const description = option.label.split(' ')[1]?.replace(/[()]/g, '');
              return (
                <div key={option.value} className={styles.checkboxItem}>
                  <input
                    type="checkbox"
                    id={`enforcer-${option.value}`}
                    checked={formData.enforcers.includes(option.value)}
                    onChange={(e) => handleEnforcerChange(option.value, e.target.checked)}
                  />
                  <label htmlFor={`enforcer-${option.value}`}>
                    {option.label.split(' ')[0]}
                  </label>
                </div>
              );
            })}
          </div>
        </div>
        
        <div className={styles.stepActions}>
          <button
            className={clsx("button button--primary", styles.nextButton)}
            onClick={() => setCurrentStep(2)}
            disabled={formData.enforcers.length === 0}
          >
            下一步
          </button>
        </div>
      </div>
    );
  };

  const privilegedCapabilities = [
    'dac_read_search', 'linux_immutable', 'net_broadcast', 'net_admin', 'ipc_lock', 'ipc_owner',
    'sys_module', 'sys_rawio', 'sys_ptrace', 'sys_pacct', 'sys_admin', 'sys_boot',
    'sys_nice', 'sys_resource', 'sys_time', 'sys_tty_config', 'lease', 'audit_control',
    'mac_override', 'mac_admin', 'syslog', 'wake_alarm', 'block_suspend', 'audit_read',
    'perfmon', 'bpf', 'checkpoint_restore'
  ];
  
  const runtimeDefaultCapabilities = [
    'audit_write', 'chown', 'dac_override', 'fowner', 'fsetid', 'kill', 'mknod', 
    'net_bind_service', 'setfcap', 'setgid', 'setpcap', 'setuid', 'sys_chroot', 'net_raw'
  ];
  
  // UI渲染函数
  const renderCapabilities = (capabilities, title, selectedCaps, handleCapabilityChange, groupKey) => {
    const allSelected = capabilities.every(cap => selectedCaps.includes(cap));
    const someSelected = capabilities.some(cap => selectedCaps.includes(cap));
    const isExpanded = groupKey === 'privileged' ? isPrivilegedExpanded : isContainerdExpanded;
    const setExpanded = groupKey === 'privileged' ? setIsPrivilegedExpanded : setIsContainerdExpanded;

    return (
      <div className={styles.formGroup}>
        <div className={styles.capabilityHeader} onClick={() => setExpanded(!isExpanded)}>
          <p>{title}</p>
          <div className={styles.capabilityStatus}>
            <label>
              <input
                type="checkbox"
                checked={allSelected}
                onChange={(e) => e.target.checked ? handleSelectAll(capabilities, groupKey) : handleDeselectAll(groupKey)}
                onClick={(e) => e.stopPropagation()}
              /> 全选
            </label>
            <span className={styles.expandIcon}>{isExpanded ? '▼' : '▶'}</span>
          </div>
        </div>
  
        {isExpanded && (
          <div className={styles.checkboxGroup}>
            {capabilities.map(cap => (
              <div key={cap} className={styles.checkboxItem}>
                <input
                  type="checkbox"
                  id={`${groupKey}-${cap}`}
                  checked={selectedCaps.includes(cap)}
                  onChange={(e) => handleCapabilityChange(cap, e.target.checked)}
                />
                <label htmlFor={`${groupKey}-${cap}`}>{cap.toUpperCase()}</label>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };
  
  // 添加全选和全不选的逻辑
  const handleSelectAll = (capabilities, groupKey) => {
    setFormData(prev => ({
      ...prev,
      capabilities: Array.from(new Set([...prev.capabilities, ...capabilities]))
    }));
  };
  
  const handleDeselectAll = (groupKey) => {
    let groupCaps = groupKey === 'privileged' ? privilegedCapabilities : runtimeDefaultCapabilities;
    setFormData(prev => ({
      ...prev,
      capabilities: prev.capabilities.filter(cap => !groupCaps.includes(cap))
    }));
  };
  
  // 渲染步骤2
  const renderStep2 = () => (
    <div className={styles.stepContent}>
      <h2>第二步：提供上下文信息</h2>
      <p>提供有关目标应用和容器的上下文信息，以便生成更加精确的策略模板。</p>
  
      <div className={styles.formGroup}>
        <h3>特性（可选）</h3>
        <p>基于您对目标应用及其容器配置的了解，提供相关信息。</p>
        <div className={styles.checkboxGroup}>
          {featureOptions.map(option => {
            const description = option.label.split('-')[1].trim();
            return (
              <div key={option.value} className={styles.checkboxItem}>
                <input
                  type="checkbox"
                  id={`feature-${option.value}`}
                  checked={formData.features.includes(option.value)}
                  onChange={(e) => handleFeatureChange(option.value, e.target.checked)}
                />
                <label htmlFor={`feature-${option.value}`}>
                  {option.label.split('-')[0].trim()}
                  <img 
                    src="/img/icon-info.svg" 
                    alt="info icon"
                    onMouseEnter={(e) => showTooltip(description, e)}
                    onMouseLeave={hideTooltip}
                    className={styles.infoIcon}
                  />
                </label>
              </div>
            );
          })}
        </div>
      </div>

      
      <div className={styles.formGroup}>
        <h3>能力（可选）</h3>
        <p>基于您对目标应用及其容器配置的了解，提供所需的能力。详见：<a href="https://man7.org/linux/man-pages/man7/capabilities.7.html" target="_blank">Linux Capability</a></p>

        {renderCapabilities(privilegedCapabilities, '请选择需要使用的敏感能力', formData.capabilities, handleCapabilityChange, 'privileged')}

        {renderCapabilities(runtimeDefaultCapabilities, '请选择需要使用的运行时默认能力', formData.capabilities, handleCapabilityChange, 'containerd')}
  
        <div className={styles.formGroup}>
          <input
            type="text"
            placeholder="请填写需要使用的能力（用英文逗号分隔）"
            className={styles.textInput}
            onBlur={(e) => {
              const extraCaps = e.target.value.split(',').map(c => c.trim()).filter(Boolean);
              setFormData(prev => ({
                ...prev,
                capabilities: Array.from(new Set([...prev.capabilities, ...extraCaps]))
              }));
            }}
          />
        </div>        
      </div>
  
      <div className={styles.formGroup}>
        <h3>行为数据（可选）</h3>
        <p>建议您使用 vArmor 的行为建模功能来收集目标应用的行为数据。然后将行为数据以 JSON 格式导出并上传，以便策略顾问根据应用的实际行为生成更精确的策略。详见：<a href="../docs/main/guides/policies_and_rules/policy_modes/behavior_modeling" target="_blank">BehaviorModeling 模式</a></p>
        <input
          type="file"
          accept="application/json"
          className={styles.fileInput}
          onChange={handleFileChange}
          key={fileName || 'empty'}
        />
        {fileName && <div className={styles.fileName}>{fileName}</div>}
      </div>
  
      <div className={styles.stepActions}>
        <button className="button button--secondary" onClick={() => setCurrentStep(1)}>上一步</button>
        <button className="button button--primary" onClick={handleGenerate}>生成策略</button>
      </div>
    </div>
  );
  

  // 渲染步骤3：生成策略模板
  const renderStep3 = () => {
    return (
      <div className={styles.stepContent}>
        <h2>第三步：生成策略模板</h2>
        <p>策略顾问使用 vArmor 的<a href="../docs/main/guides/policies_and_rules/built_in_rules" target="_blank">内置规则</a>生成了策略模板，您可以基于此模板构建最终的加固策略。</p>
        <p>注意事项：
          <ul>
            <li>策略模板默认开启违规审计特性 (auditViolations:true)。</li>
            <li>策略模板默认开启更新存量工作负载的特性 (updateExistingWorkloads:true)，在创建、删除策略时 vArmor 会对符合条件的工作负载进行滚动更新。</li>
            <li>策略模板默认不使用<a href="../docs/main/guides/policies_and_rules/built_in_rules/attack_protection#restricting-specific-executable" target="_blank">限制特定可执行文件</a>的特性。</li>
            <li>除非提供行为数据，否则策略模板不使用任何<a href="../docs/main/guides/policies_and_rules/built_in_rules/attack_protection#disabling-sensitive-operations" target="_blank">禁止敏感操作</a>的内置规则。</li>
          </ul>
        </p>

        <div className={styles.resultContainer}>
          <div className={styles.resultHeader}>
            <h3>策略模板</h3>
          </div>
          <pre className={styles.codeBlock}>
            {outputYAML}
          </pre>
        </div>
      
        <div className={styles.stepActions}>
          <button
            className={clsx("button button--secondary", styles.backButton)}
            onClick={() => setCurrentStep(2)}
          >
            上一步
          </button>
          <button 
              className={clsx("button button--primary", styles.copyButton)}
              onClick={() => {
                navigator.clipboard.writeText(outputYAML);
                setTooltipContent('复制成功');
                setTooltipVisible(true);
                setTimeout(() => setTooltipVisible(false), 2000);
              }}
            >
              复制内容
            </button>
              
        </div>

				{tooltipVisible && (
              <div 
                className={styles.copyTooltip}
                style={{ left: tooltipPosition.x, top: tooltipPosition.y + 20 }}
              >
                {tooltipContent}
              </div>
        )}

      </div>
    );
  };



  // 渲染当前步骤
  const renderCurrentStep = () => {
    switch (currentStep) {
      case 1:
        return renderStep1();
      case 2:
        return renderStep2();
      case 3:
        return renderStep3();
      default:
        return renderStep1();
    }
  };

  return (
    <Layout
      title="vArmor 策略顾问"
      description="生成 vArmor 策略模板"
    >
      <div className="container margin-vert--lg">
        <div className="row">
          <div className="col col--8 col--offset-2">
            <h1>vArmor 策略顾问</h1>
            <p className="hero__subtitle">
              通过简单步骤快速生成 EnhanceProtect 模式的策略模板，助力零基础构建加固策略。
            </p>
            
            <div className={styles.policyGeneratorContainer}>
              {renderStepNav()}
              {renderCurrentStep()}
              
              {/* Tooltip */}
              {tooltipVisible && (
                <div 
                  className={styles.tooltip} 
                  style={{
                    left: `${tooltipPosition.x + 10}px`,
                    top: `${tooltipPosition.y + 10}px`,
                  }}
                >
                  {tooltipContent}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}