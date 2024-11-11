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


def retrieve_capabilities_from_model(armor_profile_model):
  caps = []
  if "data" in armor_profile_model and \
    "dynamicResult" in armor_profile_model["data"] and \
    "apparmor" in armor_profile_model["data"]["dynamicResult"] and \
    "capabilities" in armor_profile_model["data"]["dynamicResult"]["apparmor"]:
    caps.extend(armor_profile_model["data"]["dynamicResult"]["apparmor"]["capabilities"])
  return caps


def retrieve_syscalls_from_model(armor_profile_model):
  if "data" in armor_profile_model and \
    "dynamicResult" in armor_profile_model["data"] and \
    "seccomp" in armor_profile_model["data"]["dynamicResult"] and \
    "syscalls" in armor_profile_model["data"]["dynamicResult"]["seccomp"]:
    return armor_profile_model["data"]["dynamicResult"]["seccomp"]["syscalls"]
  return []


def retrieve_executions_from_model(armor_profile_model):
  executions = []
  if "data" in armor_profile_model and \
    "dynamicResult" in armor_profile_model["data"] and \
    "apparmor" in armor_profile_model["data"]["dynamicResult"] and \
    "executions" in armor_profile_model["data"]["dynamicResult"]["apparmor"]:

    for execution in armor_profile_model["data"]["dynamicResult"]["apparmor"]["executions"]:
      executions.append(os.path.basename(execution))

  return executions


def retrieve_files_from_model(armor_profile_model):
  files = []
  if "data" in armor_profile_model and \
    "dynamicResult" in armor_profile_model["data"] and \
    "apparmor" in armor_profile_model["data"]["dynamicResult"] and \
    "files" in armor_profile_model["data"]["dynamicResult"]["apparmor"]:

    files.extend(armor_profile_model["data"]["dynamicResult"]["apparmor"]["files"])

  return files
