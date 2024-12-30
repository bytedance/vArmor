import os, json, yaml, argparse, sys
from argparse import RawTextHelpFormatter
from utils import *

def skip_the_rule_with_context(rule, enforcers, app_features, app_capabilities):
  if not has_common_item(enforcers, rule["enforcers"]):
    return True

  if "conflicts" in rule:
    if "features" in rule["conflicts"]:
      if has_common_item(rule["conflicts"]["features"], app_features):
        return True
    if "capabilities" in rule["conflicts"]:
      if has_common_item(rule["conflicts"]["capabilities"], app_capabilities):
        return True

  if "applicable" in rule:
    if "features" in rule["applicable"]:
      if has_common_item(rule["applicable"]["features"], app_features):
        return False
    if "capabilities" in rule["applicable"]:
      if has_common_item(rule["applicable"]["capabilities"], app_capabilities):
        return False
    return True

  return False


def skip_the_rule_with_model_data(rule, enforcers, armor_profile_model):
  if not has_common_item(enforcers, rule["enforcers"]):
    return True

  if "conflicts" in rule:
    if "capabilities" in rule["conflicts"]:
      model_caps = retrieve_capabilities_from_model(armor_profile_model)
      return has_common_item(rule["conflicts"]["capabilities"], model_caps)

    if "syscalls" in rule["conflicts"]:
      syscalls = retrieve_syscalls_from_model(armor_profile_model)
      return has_common_item(rule["conflicts"]["syscalls"], syscalls)

    if "executions" in rule["conflicts"]:
      executions = retrieve_executions_from_model(armor_profile_model)
      return has_common_item(rule["conflicts"]["executions"], executions)

    if "files" in rule["conflicts"]:
      files = retrieve_files_from_model(armor_profile_model)
      return files_conflict_with_rule(rule["conflicts"]["files"], files)

  return False


def set_enforcer(policy, enforcers):
  if "AppArmor" not in policy["enforcer"] and "apparmor" in enforcers:
      policy["enforcer"] += "AppArmor"
  if "BPF" not in policy["enforcer"] and "bpf" in enforcers:
    policy["enforcer"] += "BPF"
  if "Seccomp" not in policy["enforcer"] and "seccomp" in enforcers:
    policy["enforcer"] += "Seccomp"


def generate_policy_template(policy, built_in_rules, enforcers, app_features, app_capabilities, armor_profile_model, debug):
  if "privileged-container" in app_features:
    policy["enhanceProtect"]["privileged"] = True

  # ========= Hardening - Securing Privileged Containers =========
  for rule in built_in_rules["escape_pattern"]:
    # Filter out the rule with context
    if skip_the_rule_with_context(rule, enforcers, app_features, app_capabilities):
      continue

    # Filter out the rule with behavior model data
    if skip_the_rule_with_model_data(rule, enforcers, armor_profile_model):
      continue

    set_enforcer(policy, enforcers)
    policy["enhanceProtect"]["hardeningRules"].append(rule["id"])
    debug_print(rule, debug)

  # ========= Hardening - Disable Capabilities =========
  if not has_common_item(["privileged-container", "dind"], app_features):
    exist_cap_rules = False
    for rule in built_in_rules["capability_set"]:
      # Filter out the rule with context
      if skip_the_rule_with_context(rule, enforcers, app_features, app_capabilities):
        continue

      # Filter out the rule with behavior model data
      if skip_the_rule_with_model_data(rule, enforcers, armor_profile_model):
        continue

      set_enforcer(policy, enforcers)
      policy["enhanceProtect"]["hardeningRules"].append(rule["id"])
      debug_print(rule, debug)
      exist_cap_rules = True
      break

    if not exist_cap_rules:
      for rule in built_in_rules["capability"]:
        # Filter out the rule with context
        if skip_the_rule_with_context(rule, enforcers, app_features, app_capabilities):
          continue

        # Filter out the rule with behavior model data
        if skip_the_rule_with_model_data(rule, enforcers, armor_profile_model):
          continue

        set_enforcer(policy, enforcers)
        policy["enhanceProtect"]["hardeningRules"].append(rule["id"])
        debug_print(rule, debug)

  # ========= Hardening - Blocking Exploit Vectors =========
  for rule in built_in_rules["blocking_exploit_vectors"]:
    # Filter out the rule with context
    if skip_the_rule_with_context(rule, enforcers, app_features, app_capabilities):
      continue

    # Filter out the rule with behavior model data
    if skip_the_rule_with_model_data(rule, enforcers, armor_profile_model):
      continue

    set_enforcer(policy, enforcers)
    policy["enhanceProtect"]["hardeningRules"].append(rule["id"])
    debug_print(rule, debug)
 
  # ========= Attack Protection - Mitigating Information Leakage =========
  for rule in built_in_rules["information_leak"]:
    # Filter out the rule with context
    if skip_the_rule_with_context(rule, enforcers, app_features, app_capabilities):
      continue

    # Filter out the rule with behavior model data
    if skip_the_rule_with_model_data(rule, enforcers, armor_profile_model):
      continue

    set_enforcer(policy, enforcers)
    policy["enhanceProtect"]["attackProtectionRules"][0]["rules"].append(rule["id"])
    debug_print(rule, debug)

  # ========= Attack Protection - Disable Sensitive Operations =========
  # Note: 
  #   We use the built-in rules of the sensitive operation category 
  #   only if the behavior model is provided.
  if armor_profile_model:
    for rule in built_in_rules["sensitive_operations"]:
      # Filter out the rule with context
      if skip_the_rule_with_context(rule, enforcers, app_features, app_capabilities):
        continue

      # Filter out the rule with behavior model data
      if skip_the_rule_with_model_data(rule, enforcers, armor_profile_model):
        continue

      set_enforcer(policy, enforcers)
      policy["enhanceProtect"]["attackProtectionRules"][0]["rules"].append(rule["id"])
      debug_print(rule, debug)

  # ========= Vulnerability Mitigation =========
  for rule in built_in_rules["vulnerability_mitigation"]:
    # Filter out the rule with context
    if skip_the_rule_with_context(rule, enforcers, app_features, app_capabilities):
      continue

    # Filter out the rule with behavior model data
    if skip_the_rule_with_model_data(rule, enforcers, armor_profile_model):
      continue

    set_enforcer(policy, enforcers)
    policy["enhanceProtect"]["vulMitigationRules"].append(rule["id"])
    debug_print(rule, debug)


def built_in_rules_advisor(built_in_rules, enforcers, app_features=[], app_capabilities=[], armor_profile_model={}, debug=False):
  policy = {
    "enforcer": "",
    "mode": "EnhanceProtect",
    "enhanceProtect": {
      "privileged": False,
      "hardeningRules": [],
      "attackProtectionRules": [
        {
          "rules": [],
          "targets": []
        }
      ],
      "vulMitigationRules": [],
    }
  }

  generate_policy_template(policy, built_in_rules, enforcers, app_features, app_capabilities, armor_profile_model, debug)

  print('''
Please take note of the following tips about the template:
  * It doesn't utilize the `Restrict Specific Executable` feature provided by the AppArmor enforcer.
  * It avoids applying any 'Disable Sensitive Operations' rules for compatibility when an ArmorProfileModel is not provided.
  * It excludes some `Vulnerability Mitigation` rules by default.

For additional information on built-in rules, please refer to the documentation: 
https://github.com/bytedance/vArmor/blob/main/docs/built_in_rules.md

You may modify the template accordingly based on the specific requirements of your scenario and environment.''')

  print("\n------------------ Template (json) ------------------\n")
  print(json.dumps(policy, indent=2))
  print("\n------------------ Template (yaml) ------------------\n")
  print(yaml.dump(policy, default_flow_style=False))


if __name__ == "__main__":
  parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter,
    description='''This program can help users generate a `.spec.policy` template with built-in rules or the behavior model data. 
The template can be a good start to craft the final policy. Please use the -f and -c command-line arguments to specify the context.

use cases: 
1). Generate a policy template that runs in EnhanceProtect mode with built-in rules supported by AppArmor and BPF enforcers.
    policy-advisor.py AppArmor,BPF -f share-containers-pid-ns -c sys_admin,net_admin,kill

2). Filter out the conflicted built-in rules with behavior model data to make the policy template more precise.
    policy-advisor.py AppArmor,BPF -f share-containers-pid-ns -c sys_admin,net_admin,kill -m model_data.json
''')

  parser.add_argument("enforcers", type=str,
    help='''The enforcers supported by the environment.
Available Values: AppArmor, BPF, Seccomp (they should be combined with commas.)
For Example: "AppArmor,BPF,Seccomp"\n''')

  parser.add_argument("-f", dest="features", type=str, default="",
    help='''The features of the target application and its container. Providing as comprehensive features as 
possible helps generate more precise policy templates.

Available Values (they should be combined with commas.):
  * privileged-container: The target application runs in a privileged container.
  * mount-sth: The target application needs to execute some mount operations in the container.
  * umount-sth: The target application needs to execute some umount operations in the container.
  * share-containers-pid-ns: The target container shares the PID namespace with sidecar containers.
  * share-host-pid-ns: The target container shares the PID namespace with host.
  * dind: The target application will create a docker in docker container.
  * require-sa: The target application needs to interact with API Server.
  * bind-privileged-socket-port: The target application needs to listen on a socket port less than 1024.
  * load-bpf: The target application needs to load eBPF programs in the container.
For Example: "privileged-container,require-sa,bind-privileged-socket-port"\n\n''')

  parser.add_argument("-c", dest="capabilities", type=str, default="",
    help='''The capabilities required by the target application and its containers. Providing the capabilities 
needed for the application explicitly helps generate more precise policy templates. For example, 
before Linux 5.8, loading BPF programs requires sys_admin capability. Since Linux 5.8, loading BPF 
programs requires sys_admin or bpf capabilities. If your application needs to load BPF 
programs, please add both sys_admin and bpf, that is "sys_admin,bpf". See CAPABILITIES(7).

Available Values: CAPABILITIES(7) without 'CAP_' prefix (they should be combined with commas).
For Example: "sys_admin,net_admin,sys_module"\n\n''')

  parser.add_argument("-m", dest="behavior_model", type=str, default="",
    help='''The behavior model data is an ArmorProfileModel object that is generated by vArmor. 
The input file must be in JSON format. You can export the data with kubectl command, such as: 
kubectl get ArmorProfileModel -n {NAMESPACE} {NAME} -o json > model.json\n\n''')

  parser.add_argument("-d", dest="debug", action="store_true", default=False, help="Print debug information.")

  args = parser.parse_args()
  enforcers = args.enforcers.lower().split(',')
  features = args.features.lower().split(',')
  capabilities = args.capabilities.lower().split(',')
  if len(features) == 1 and '' in features:
    features = []
  if len(capabilities) == 1 and '' in capabilities:
    capabilities = []

  if args.behavior_model and not os.path.exists(args.behavior_model):
    print("[!] The model file isn't exist.")
    sys.exit(1)

  with open(os.path.join(current_dir, "./built-in-rules.json"), "r") as f:
    built_in_rules = json.load(f)

    if args.behavior_model:
      with open(args.behavior_model, "r") as model_f:
        armor_profile_model = json.load(model_f)
        built_in_rules_advisor(built_in_rules, enforcers, features, capabilities, armor_profile_model, args.debug)
    else:
      built_in_rules_advisor(built_in_rules, enforcers, features, capabilities, {}, args.debug)
