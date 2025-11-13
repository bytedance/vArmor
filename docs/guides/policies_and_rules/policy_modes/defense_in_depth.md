# The DefenseInDepth Mode

English | [简体中文](defense_in_depth.zh_CN.md)

# DefenseInDepth Mode

## Introduction

The Mandatory Access Control (MAC) policy based on the **Deny-by-Default** security model can significantly enhance security. However, the key challenge lies in formulating security profiles that balance security and compatibility — ensuring they do not affect application operations while providing in-depth protection.

The DefenseInDepth mode is an experimental feature of vArmor. It aims to combine various technologies (behavior modeling, violation auditing, LLM-assisted analysis and processing, etc.) to provide you with a low-threshold and highly user-friendly solution for generating and managing profiles for microservices.

Currently, only AppArmor and Seccomp enforcers support the DefenseInDepth mode.

## Core Capabilities

Currently, the DefenseInDepth mode supports the use of two types of profiles to protect target workloads.

* Profiles generated through the BehaviorModeling mode
* Custom profiles

It also provides features such as the observation mode and custom rule stacking, allowing you to conduct trial runs of profiles and perform dynamic tuning.

## Use Cases

* Build allowlist profiles for containerized microservices
* Provide the ability to manage custom profiles
* Optimize profiles in combination with audit logs

For specific operations, please refer to the [API Documentation](../../../getting_started/interface_specification.md#defenseindepth) and examples in the project repository.
