import os, re

global current_dir
current_dir = os.path.dirname(os.path.realpath(__file__))

def debug_print(rule, debug):
  if debug:
    print("--------------")
    print(rule["id"])


def has_common_item(list_one, list_two):
  for item in list_one:
    if item == '*':
      return True
    if item in list_two:
      return True
  return False


def files_conflict_with_rule(file_rules, files):
  for file in files:
    for file_rule in file_rules:
      path = file["oldPath"] if len(file["oldPath"])>0 else file["path"]
      if re.search(file_rule["path_regex"], path) and has_common_item(file_rule["permissions"], file["permissions"]):
        return True

  return False


def retrieve_capabilities_from_behavior_data(behavior_data):
  caps = []
  caps.extend(behavior_data.get("data", {}).get("dynamicResult", {}).get("appArmor", {}).get("capabilities", []))
  caps.extend(behavior_data.get("data", {}).get("dynamicResult", {}).get("bpf", {}).get("syscalls", []))
  return caps


def retrieve_syscalls_from_behavior_data(behavior_data):
  return behavior_data.get("data", {}).get("dynamicResult", {}).get("seccomp", {}).get("syscalls", [])


def retrieve_executions_from_behavior_data(behavior_data):
  executions = []
  for execution in behavior_data.get("data", {}).get("dynamicResult", {}).get("appArmor", {}).get("executions", []):
    executions.append(os.path.basename(execution))
  for execution in behavior_data.get("data", {}).get("dynamicResult", {}).get("bpf", {}).get("executions", []):
    executions.append(os.path.basename(execution))
  return executions


def retrieve_files_from_behavior_data(behavior_data):
  files = []
  files.extend(behavior_data.get("data", {}).get("dynamicResult", {}).get("appArmor", {}).get("files", []))
  files.extend(behavior_data.get("data", {}).get("dynamicResult", {}).get("bpf", {}).get("files", []))
  return files
