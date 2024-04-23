import os, json, yaml, argparse
from argparse import RawTextHelpFormatter

def has_common_item(list_one, list_two):
  for item in list_one:
    if item == '*':
      return True
    if item in list_two:
      return True

  return False


def skip_the_rule(rule, app_features, app_capabilities):
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


def set_enforcer(policy, rule):
  if "AppArmor" not in policy["enforcer"] and \
      "AppArmor" in rule["enforcers"]:      
      policy["enforcer"] += "AppArmor"
  if "BPF" not in policy["enforcer"] and \
    "BPF" in rule["enforcers"]:      
    policy["enforcer"] += "BPF"
  if "Seccomp" not in policy["enforcer"] and \
    "Seccomp" in rule["enforcers"]:      
    policy["enforcer"] += "Seccomp"


def debug_print(rule, debug):
  if debug:
    print("--------------")
    print(rule["id"])


def generate_policy_with_context(policy, built_in_rules, app_features, app_capabilities, armor_profile_model, debug):
  if "privileged-container" in app_features:
    policy["enhanceProtect"]["privileged"] = True

  # Hardening - Securing Privileged Containers
  for rule in built_in_rules["escape_pattern"]:
    if skip_the_rule(rule, app_features, app_capabilities):
      continue

    set_enforcer(policy, rule)
    policy["enhanceProtect"]["hardeningRules"].append(rule["id"])
    debug_print(rule, debug)

  # Hardening - Disable Capabilities
  if not has_common_item(["privileged-container", "dind"], app_features):
    exist_cap_rules = False
    for rule in built_in_rules["capability_set"]:
      if skip_the_rule(rule, app_features, app_capabilities):
        continue

      set_enforcer(policy, rule)
      policy["enhanceProtect"]["hardeningRules"].append(rule["id"])
      debug_print(rule, debug)
      exist_cap_rules = True
      break

    if not exist_cap_rules:
      for rule in built_in_rules["capability"]:
        if skip_the_rule(rule, app_features, app_capabilities):
          continue

        set_enforcer(policy, rule)
        policy["enhanceProtect"]["hardeningRules"].append(rule["id"])
        debug_print(rule, debug)

  # Hardening - Blocking Exploit Vectors
  for rule in built_in_rules["blocking_exploit_vectors"]:
    if skip_the_rule(rule, app_features, app_capabilities):
      continue

    set_enforcer(policy, rule)
    policy["enhanceProtect"]["hardeningRules"].append(rule["id"])
    debug_print(rule, debug)
 
  # Attack Protection - Mitigating Information Leakage
  for rule in built_in_rules["information_leak"]:
    if skip_the_rule(rule, app_features, app_capabilities):
      continue

    set_enforcer(policy, rule)
    policy["enhanceProtect"]["attackProtectionRules"][0]["rules"].append(rule["id"])
    debug_print(rule, debug)

  # Attack Protection - Disable Sensitive Operations
  if armor_profile_model:
    for rule in built_in_rules["sensitive_operations"]:
      if skip_the_rule(rule, app_features, app_capabilities):
        continue
      set_enforcer(policy, rule)
      policy["enhanceProtect"]["attackProtectionRules"][0]["rules"].append(rule["id"])
      debug_print(rule, debug)

  # Vulnerability Mitigation
  for rule in built_in_rules["vulnerability_mitigation"]:
    if skip_the_rule(rule, app_features, app_capabilities):
      continue

    set_enforcer(policy, rule)
    policy["enhanceProtect"]["attackProtectionRules"][0]["rules"].append(rule["id"])
    debug_print(rule, debug)


def built_in_rules_advisor(built_in_rules, app_features=[], app_capabilities=[], armor_profile_model={}, debug=False):
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

  generate_policy_with_context(policy, built_in_rules, app_features, app_capabilities, armor_profile_model, debug)

  print('''
Please take note of the following regarding the template configurations:
  * It doesn't utilize the `Restrict Specific Executable` feature provided by the AppArmor enforcer.
  * It avoids applying any 'Disable Sensitive Operations' rules for compatibility when an ArmorProfileModel is not provided.
  * It excludes some `Vulnerability Mitigation` rules by default.

For additional information on built-in rules, please refer to the documentation: 
https://github.com/bytedance/vArmor/blob/main/docs/built_in_rules.md

You may tailor the policy settings accordingly based on the specific requirements of your scenario 
and environment.''')

  print("\n------------------ Template (json) ------------------\n")
  print(json.dumps(policy, indent=2))
  print("\n------------------ Template (yaml) ------------------\n")
  print(yaml.dump(policy, default_flow_style=False))


#
# TODO:
#   v0.5.8 - The disallow-create-user-ns rule will no longer conflict with sys_admin
#
if __name__ == "__main__":
  parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter,
    description='''This program can help users generate a `.spec.policy` template with the target context. The template can be a good
start to create the final policy. Please use the -f and -c command-line arguments to specify the context.

For Example: policy-advisor.py -f share-containers-pid-ns -c sys_admin,net_admin,kill
''')

  parser.add_argument("-f", dest="features", type=str, default="",
    help='''The features of the target application and its container.

Available Values (They can be combined with commas.): 
  * privileged-container: The target application runs in a privileged container.
  * mount-sth: The target application will mount some files/devices in the container.
  * umount-sth: The target application will unmount some files/devices in the container.
  * share-containers-pid-ns: The target container shares the PID namespace with sidecar containers.
  * share-host-pid-ns: The target container shares the PID namespace with host.
  * dind: The target application will create a docker in docker container.
  * require-sa: The target application will interact with API Server
  * bind-privileged-socket-port: The target application will listen on a socket port less than 1024.

For Example:
    privileged-container,require-sa,bind-privileged-socket-port\n\n''')

  parser.add_argument("-c", dest="capabilities", type=str, default="",
    help='''The capabilities of target application and its container are required. Providing as
comprehensive a capability as possible helps generate more accurate strategy templates for you. 
For example, before Linux 5.8, loading BPF programs required sys_admin capability. Since Linux 5.8, 
loading BPF programs requires bpf, perfon or net_admin capabilities. If your application needs to 
load BPF programs, please add both sys_admin and bpf, that is "sys_admin,bpf". See CAPABILITIES(7).

Available Values: CAPABILITIES(7) without 'CAP_' prefix (they can be combined with commas). 

For Example:
    sys_admin,net_admin,sys_module,...\n''')

  parser.add_argument("-d", dest="debug", type=bool, default=False, help="Print debug information.")

  args = parser.parse_args()

  features = args.features.lower().split(',')
  capabilities = args.capabilities.lower().split(',')

  current_dir = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(current_dir, "./built-in-rules.json"), "r") as f:
    built_in_rules = json.load(f)

    if os.path.exists(os.path.join(current_dir, "./armor-profile-model.json")):
      with open(os.path.join(current_dir, "./armor-profile-model.json"), "r") as model_f:
        armor_profile_model = json.load(model_f)
        built_in_rules_advisor(built_in_rules, features, capabilities, armor_profile_model, args.debug)
    else:
      built_in_rules_advisor(built_in_rules, features, capabilities, {}, args.debug)
