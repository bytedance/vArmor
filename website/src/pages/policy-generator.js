// src/pages/policy-generator.js

import React, { useState } from 'react';
import Layout from '@theme/Layout';
import styles from './policy-generator.module.css';
import Link from '@docusaurus/Link';
import clsx from 'clsx';
import CodeBlock from '@theme/CodeBlock';
import ThemeImage from '@site/src/components/ThemeImage';

// 策略生成器组件
function PolicyGenerator() {
  // 步骤状态
  const [currentStep, setCurrentStep] = useState(1);
  
  // 表单状态
  const [formData, setFormData] = useState({
    enforcer: '',
    policyMode: 'EnhanceProtect',
    features: [],
    capabilities: [],
    rules: []
  });

  // 生成的策略
  const [generatedPolicy, setGeneratedPolicy] = useState(null);
  // 生成的YAML格式策略
  const [generatedYaml, setGeneratedYaml] = useState('');

  // 可用的执行器选项
  const enforcerOptions = [
    { value: 'AppArmor', label: 'AppArmor' },
    { value: 'BPF', label: 'BPF' },
    { value: 'Seccomp', label: 'Seccomp' }
  ];

  // 策略模式选项
  const policyModeOptions = [
    { value: 'AlwaysAllow', label: '始终允许 (AlwaysAllow)' },
    { value: 'RuntimeDefault', label: '运行时默认 (RuntimeDefault)' },
    { value: 'EnhanceProtect', label: '增强保护 (EnhanceProtect)' },
    { value: 'BehaviorModeling', label: '行为建模 (BehaviorModeling)' },
    { value: 'DefenseInDepth', label: '纵深防御 (DefenseInDepth)' }
  ];

  // 应用特性选项
  const featureOptions = [
    { value: 'privileged-container', label: '特权容器 (privileged-container)' },
    { value: 'mount-sth', label: '需要执行挂载操作 (mount-sth)' },
    { value: 'umount-sth', label: '需要执行卸载操作 (umount-sth)' },
    { value: 'share-containers-pid-ns', label: '与边车容器共享PID命名空间 (share-containers-pid-ns)' },
    { value: 'share-host-pid-ns', label: '与主机共享PID命名空间 (share-host-pid-ns)' },
    { value: 'dind', label: '容器中的Docker (dind)' },
    { value: 'require-sa', label: '需要与API服务器交互 (require-sa)' },
    { value: 'bind-privileged-socket-port', label: '需要监听特权端口 (bind-privileged-socket-port)' },
    { value: 'load-bpf', label: '需要加载eBPF程序 (load-bpf)' }
  ];

  // 常用能力选项
  const capabilityOptions = [
    { value: 'sys_admin', label: 'SYS_ADMIN' },
    { value: 'net_admin', label: 'NET_ADMIN' },
    { value: 'sys_ptrace', label: 'SYS_PTRACE' },
    { value: 'sys_module', label: 'SYS_MODULE' },
    { value: 'dac_override', label: 'DAC_OVERRIDE' },
    { value: 'dac_read_search', label: 'DAC_READ_SEARCH' },
    { value: 'kill', label: 'KILL' },
    { value: 'bpf', label: 'BPF' }
  ];

  // 内置规则分类
  const ruleCategories = [
    {
      name: '加固 (Hardening)',
      rules: [
        { id: 'disallow-write-core-pattern', label: '禁止修改procfs的core_pattern', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-mount-securityfs', label: '禁止挂载securityfs', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-mount-procfs', label: '禁止重新挂载procfs', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-write-release-agent', label: '禁止修改cgroupfs的release_agent', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-mount-cgroupfs', label: '禁止重新挂载cgroupfs', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-cap-sys-admin', label: '禁用SYS_ADMIN能力', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-cap-sys-ptrace', label: '禁用SYS_PTRACE能力', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-cap-sys-module', label: '禁用SYS_MODULE能力', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-cap-dac-read-search', label: '禁用DAC_READ_SEARCH能力', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-cap-dac-override', label: '禁用DAC_OVERRIDE能力', enforcer: ['AppArmor', 'BPF'] }
      ]
    },
    {
      name: '攻击防护 (Attack Protection)',
      rules: [
        { id: 'mitigate-sa-leak', label: '缓解ServiceAccount令牌泄露', enforcer: ['AppArmor', 'BPF'] },
        { id: 'mitigate-disk-device-number-leak', label: '缓解主机磁盘设备号泄露', enforcer: ['AppArmor', 'BPF'] },
        { id: 'mitigate-overlayfs-leak', label: '缓解容器overlayfs路径泄露', enforcer: ['AppArmor', 'BPF'] },
        { id: 'mitigate-host-ip-leak', label: '缓解主机IP泄露', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-metadata-service', label: '禁止访问元数据服务', enforcer: ['BPF'] },
        { id: 'disallow-ptrace', label: '禁止ptrace', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-process-kill', label: '禁止杀死进程', enforcer: ['AppArmor', 'BPF'] },
        { id: 'disallow-new-privileges', label: '禁止获取新特权', enforcer: ['AppArmor', 'BPF'] }
      ]
    },
    {
      name: '漏洞缓解 (Vulnerability Mitigation)',
      rules: [
        { id: 'mitigate-cve-2019-5736', label: '缓解CVE-2019-5736 (runc漏洞)', enforcer: ['AppArmor', 'BPF'] },
        { id: 'mitigate-cve-2022-0185', label: '缓解CVE-2022-0185 (Linux内核漏洞)', enforcer: ['AppArmor', 'BPF'] },
        { id: 'mitigate-cve-2022-0492', label: '缓解CVE-2022-0492 (cgroup漏洞)', enforcer: ['AppArmor', 'BPF'] },
        { id: 'mitigate-cve-2022-0847', label: '缓解CVE-2022-0847 (Dirty Pipe漏洞)', enforcer: ['AppArmor', 'BPF'] },
        { id: 'mitigate-cve-2022-23222', label: '缓解CVE-2022-23222 (Linux内核漏洞)', enforcer: ['AppArmor', 'BPF'] }
      ]
    }
  ];

  // 处理执行器选择变更
  const handleEnforcerChange = (enforcer) => {
    setFormData({
      ...formData,
      enforcer: enforcer,
      rules: [] // 重置规则选择
    });
  };

  // 处理策略模式变更
  const handlePolicyModeChange = (mode) => {
    setFormData({
      ...formData,
      policyMode: mode,
      rules: [] // 重置规则选择
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

  // 处理规则选择变更
  const handleRuleChange = (ruleId, checked) => {
    let updatedRules = [...formData.rules];
    
    if (checked) {
      updatedRules.push(ruleId);
    } else {
      updatedRules = updatedRules.filter(r => r !== ruleId);
    }
    
    setFormData({
      ...formData,
      rules: updatedRules
    });
  };

  // 将JSON对象转换为YAML字符串
  const jsonToYaml = (obj, indent = 0) => {
    if (!obj) return '';
    
    let yaml = '';
    const spaces = ' '.repeat(indent);
    
    if (Array.isArray(obj)) {
      if (obj.length === 0) return spaces + '[]';
      
      for (const item of obj) {
        if (typeof item === 'object' && item !== null) {
          yaml += spaces + '- ' + jsonToYaml(item, indent + 2).trimStart() + '\n';
        } else {
          yaml += spaces + '- ' + item + '\n';
        }
      }
      return yaml;
    } else if (typeof obj === 'object' && obj !== null) {
      for (const key in obj) {
        const value = obj[key];
        
        if (value === undefined || value === null) continue;
        
        if (Array.isArray(value)) {
          if (value.length === 0) {
            yaml += spaces + key + ': []\n';
          } else {
            yaml += spaces + key + ':\n';
            yaml += jsonToYaml(value, indent + 2);
          }
        } else if (typeof value === 'object') {
          yaml += spaces + key + ':\n';
          yaml += jsonToYaml(value, indent + 2);
        } else {
          yaml += spaces + key + ': ' + value + '\n';
        }
      }
      return yaml;
    } else {
      return obj.toString();
    }
  };

  // 生成策略
  const generatePolicy = () => {
    // 构建策略对象
    const policy = {
      apiVersion: "crd.varmor.org/v1beta1",
      kind: "VarmorPolicy",
      metadata: {
        name: "generated-policy",
        namespace: "default"
      },
      spec: {
        target: {
          kind: "Deployment",
          selector: {
            matchLabels: {
              app: "your-app"
            }
          }
        },
        policy: {
          mode: formData.policyMode,
          enforcer: formData.enforcer
        }
      }
    };

    // 如果是增强保护模式，添加规则
    if (formData.policyMode === 'EnhanceProtect') {
      policy.spec.policy.enhanceProtect = {};
      
      // 根据选择的规则分类添加
      const hardeningRules = [];
      const attackProtectionRules = [];
      const vulMitigationRules = [];
      
      formData.rules.forEach(ruleId => {
        // 查找规则所属分类
        for (const category of ruleCategories) {
          const rule = category.rules.find(r => r.id === ruleId);
          if (rule) {
            if (category.name.includes('加固')) {
              hardeningRules.push(ruleId);
            } else if (category.name.includes('攻击防护')) {
              attackProtectionRules.push(ruleId);
            } else if (category.name.includes('漏洞缓解')) {
              vulMitigationRules.push(ruleId);
            }
            break;
          }
        }
      });

      // 如果特性中包含特权容器，设置privileged为true
      if (formData.features.includes('privileged-container')) {
        policy.spec.policy.enhanceProtect.privileged = true;
      }

      // 添加规则到策略中
      if (hardeningRules.length > 0) {
        policy.spec.policy.enhanceProtect.hardeningRules = hardeningRules;
      }
      
      if (attackProtectionRules.length > 0) {
        policy.spec.policy.enhanceProtect.attackProtectionRules = [{
          rules: attackProtectionRules
        }];
      }
      
      if (vulMitigationRules.length > 0) {
        policy.spec.policy.enhanceProtect.vulMitigationRules = vulMitigationRules;
      }

      // 如果是Seccomp执行器，添加syscallRawRules
      if (formData.enforcer === 'Seccomp') {
        policy.spec.policy.enhanceProtect.syscallRawRules = [
          {
            names: ['ptrace', 'mknod', 'mount', 'sysctl'],
            action: 'SCMP_ACT_ERRNO'
          }
        ];
      }
    }

    // 设置生成的策略
    setGeneratedPolicy(policy);
    
    // 将策略转换为YAML格式
    const yamlContent = jsonToYaml(policy);
    setGeneratedYaml(yamlContent);
    
    // 移动到最后一步
    setCurrentStep(4);
  };

};

// 渲染步骤导航
const renderStepNav = () => {
  return (
    <div className={styles.stepNav}>
      <div className={clsx(styles.stepItem, currentStep >= 1 && styles.activeStep)} onClick={() => setCurrentStep(1)}>
        <div className={styles.stepNumber}>1</div>
        <div className={styles.stepLabel}>选择执行器</div>
      </div>
      <div className={clsx(styles.stepItem, currentStep >= 2 && styles.activeStep)} onClick={() => formData.enforcer && setCurrentStep(2)}>
        <div className={styles.stepNumber}>2</div>
        <div className={styles.stepLabel}>应用特性</div>
      </div>
      <div className={clsx(styles.stepItem, currentStep >= 3 && styles.activeStep)} onClick={() => formData.enforcer && setCurrentStep(3)}>
        <div className={styles.stepNumber}>3</div>
        <div className={styles.stepLabel}>选择规则</div>
      </div>
      <div className={clsx(styles.stepItem, currentStep >= 4 && styles.activeStep)} onClick={() => generatedPolicy && setCurrentStep(4)}>
        <div className={styles.stepNumber}>4</div>
        <div className={styles.stepLabel}>生成策略</div>
      </div>
    </div>
  );
};

// 渲染步骤1：选择执行器
const renderStep1 = () => {
  return (
    <div className={styles.stepContent}>
      <h2>第一步：选择执行器和策略模式</h2>
      <p>请选择您的环境支持的执行器类型和策略模式。</p>
      
      <div className={styles.formGroup}>
        <h3>执行器</h3>
        <div className={styles.optionGroup}>
          {enforcerOptions.map((option) => (
            <div key={option.value} className={styles.optionItem}>
              <input
                type="radio"
                id={`enforcer-${option.value}`}
                name="enforcer"
                checked={formData.enforcer === option.value}
                onChange={() => handleEnforcerChange(option.value)}
              />
              <label htmlFor={`enforcer-${option.value}`}>{option.label}</label>
            </div>
          ))}
        </div>
      </div>

      <div className={styles.formGroup}>
        <h3>策略模式</h3>
        <div className={styles.optionGroup}>
          {policyModeOptions.map((option) => (
            <div key={option.value} className={styles.optionItem}>
              <input
                type="radio"
                id={`mode-${option.value}`}
                name="policyMode"
                checked={formData.policyMode === option.value}
                onChange={() => handlePolicyModeChange(option.value)}
              />
              <label htmlFor={`mode-${option.value}`}>{option.label}</label>
            </div>
          ))}
        </div>
      </div>

      <div className={styles.stepActions}>
        <button 
          className={clsx("button button--primary", styles.nextButton)} 
          onClick={() => setCurrentStep(2)} 
          disabled={!formData.enforcer}
        >
          下一步
        </button>
      </div>
    </div>
  );
};

// 渲染步骤2：应用特性和能力
const renderStep2 = () => {
  return (
    <div className={styles.stepContent}>
      <h2>第二步：应用特性和能力</h2>
      <p>请选择您的应用具有的特性和需要的能力。</p>
      
      <div className={styles.formGroup}>
        <h3>应用特性</h3>
        <div className={styles.checkboxGroup}>
          {featureOptions.map((option) => (
            <div key={option.value} className={styles.checkboxItem}>
              <input
                type="checkbox"
                id={`feature-${option.value}`}
                checked={formData.features.includes(option.value)}
                onChange={(e) => handleFeatureChange(option.value, e.target.checked)}
              />
              <label htmlFor={`feature-${option.value}`}>{option.label}</label>
            </div>
          ))}
        </div>
      </div>

      <div className={styles.formGroup}>
        <h3>应用需要的能力</h3>
        <div className={styles.checkboxGroup}>
          {capabilityOptions.map((option) => (
            <div key={option.value} className={styles.checkboxItem}>
              <input
                type="checkbox"
                id={`capability-${option.value}`}
                checked={formData.capabilities.includes(option.value)}
                onChange={(e) => handleCapabilityChange(option.value, e.target.checked)}
              />
              <label htmlFor={`capability-${option.value}`}>{option.label}</label>
            </div>
          ))}
        </div>
      </div>

      <div className={styles.stepActions}>
        <button 
          className={clsx("button button--secondary", styles.backButton)} 
          onClick={() => setCurrentStep(1)}
        >
          上一步
        </button>
        <button 
          className={clsx("button button--primary", styles.nextButton)} 
          onClick={() => setCurrentStep(3)}
        >
          下一步
        </button>
      </div>
    </div>
  );
};

// 渲染步骤3：选择规则
const renderStep3 = () => {
  // 根据选择的执行器过滤规则
  const filteredRuleCategories = ruleCategories.map(category => {
    return {
      ...category,
      rules: category.rules.filter(rule => rule.enforcer.includes(formData.enforcer))
    };
  }).filter(category => category.rules.length > 0);

  return (
    <div className={styles.stepContent}>
      <h2>第三步：选择规则</h2>
      <p>请选择您需要应用的内置规则。</p>
      
      {filteredRuleCategories.map((category, index) => (
        <div key={index} className={styles.formGroup}>
          <h3>{category.name}</h3>
          <div className={styles.checkboxGroup}>
            {category.rules.map((rule) => (
              <div key={rule.id} className={styles.checkboxItem}>
                <input
                  type="checkbox"
                  id={`rule-${rule.id}`}
                  checked={formData.rules.includes(rule.id)}
                  onChange={(e) => handleRuleChange(rule.id, e.target.checked)}
                />
                <label htmlFor={`rule-${rule.id}`}>{rule.label}</label>
              </div>
            ))}
          </div>
        </div>
      ))}

      <div className={styles.stepActions}>
        <button 
          className={clsx("button button--secondary", styles.backButton)} 
          onClick={() => setCurrentStep(2)}
        >
          上一步
        </button>
        <button 
          className={clsx("button button--primary", styles.nextButton)} 
          onClick={generatePolicy}
        >
          生成策略
        </button>
      </div>
    </div>
  );
};

// 渲染步骤4：生成策略
const renderStep4 = () => {
  return (
    <div className={styles.stepContent}>
      <h2>第四步：生成策略</h2>
      <p>您的vArmor策略已生成，可以复制并应用到您的Kubernetes集群。</p>
      
      <div className={styles.policyPreview}>
        <CodeBlock language="yaml">
          {generatedYaml}
        </CodeBlock>
      </div>

      <div className={styles.stepActions}>
        <button 
          className={clsx("button button--secondary", styles.backButton)} 
          onClick={() => setCurrentStep(3)}
        >
          上一步
        </button>
        <button 
          className={clsx("button button--primary", styles.nextButton)} 
          onClick={() => {
            // 复制到剪贴板
            navigator.clipboard.writeText(generatedYaml);
            alert('策略已复制到剪贴板');
          }}
        >
          复制策略
        </button>
      </div>
    </div>
  );
};

// 渲染当前步骤内容
const renderCurrentStep = () => {
  switch (currentStep) {
    case 1:
      return renderStep1();
    case 2:
      return renderStep2();
    case 3:
      return renderStep3();
    case 4:
      return renderStep4();
    default:
      return renderStep1();
  }
};



export default function PolicyGeneratorPage() {
	return (
		<Layout
			title="vArmor 策略生成器"
			description="通过简单的步骤生成vArmor策略，保护您的Kubernetes工作负载">
			<header className={clsx('hero', styles.heroBanner)}>
				<div className={styles.heroBgImage}></div>
				<div className="container">
					<div className={styles.heroContent}>
						<div className={styles.heroText}>
							<h1 className={stgiyles.heroTitle}>vArmor 策略生成器</h1>
							<p className={styles.heroTagline}>
								通过简单的步骤生成vArmor策略，保护您的Kubernetes工作负载
							</p>
						</div>
					</div>
				</div>
			</header>
			<main className={styles.policyGeneratorContainer}>
				<div className="container">
					{renderStepNav()}
					{renderCurrentStep()}
				</div>
			</main>
		</Layout>
	);
	
}