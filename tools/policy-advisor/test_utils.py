import unittest
from utils import files_conflict_with_rule

class TestFunctions(unittest.TestCase):
  def test_files_conflict_with_rule(self):
    data = {
      "disable-write-etc": {
        "rules": [
            {
              "path_regex": r"^\/etc$|^\/etc\/|\/containerd\/.*\/fs\/root\/etc$|\/containerd\/.*\/fs\/root\/etc\/",
              "permissions": [
                "w",
                "a"
              ]
            }
          ],
        "testcases": [
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/etc/nshadow",
                "permissions": [
                    "r",
                    "w"
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4158/fs/root/etc/nshadow",
                "permissions": [
                    "r",
                    "w"
                ]
              }
            ]
          },
          {
            "conflict": False,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4158/fs/root/etc/nshadow",
                "permissions": [
                    "r"
                ]
              }
            ]
          },
          {
            "conflict": False,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/etct/nshadow",
                "permissions": [
                    "r",
                    "w"
                ]
              }
            ]
          },
          {
            "conflict": False,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4158/fs/root/etct/nshadow",
                "permissions": [
                    "r",
                    "w"
                ]
              }
            ]
          },
        ]
      },
      "mitigate-sa-leak": {
        "rules": [
          {
            "path_regex": r"\/run\/secrets\/kubernetes.io\/serviceaccount\/",
            "permissions": [
              "r"
            ]
          }
        ],
        "testcases": [
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/run/secrets/kubernetes.io/serviceaccount/token",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/run/secrets/kubernetes.io/serviceaccount/..2024_06_11_08_19_55.1685806518/token",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": False,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/root/secrets/kubernetes.io/serviceaccount/..2024_06_11_08_19_55.1685806518/token",
                "permissions": [
                    "r",
                ]
              }
            ]
          }
        ]
      },
      "mitigate-disk-device-number-leak": {
        "rules": [
            {
              "path_regex": r"\/proc\/partitions|\/proc\/.*\/mountinfo",
              "permissions": [
                "r"
              ]
            }
          ],
        "testcases": [
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/self/mountinfo",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/111/mountinfo",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/1/root/proc/thread-self/mountinfo",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/self/task/8/mountinfo",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/self/task/8/mounts",
                "permissions": [
                    "r",
                ]
              },
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/self/task/8/mountinfo",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": False,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/self/task/8/mounts",
                "permissions": [
                    "r",
                ]
              },
            ]
          },
        ]
      },
      "mitigate-overlayfs-leak": {
        "rules": [
            {
              "path_regex": r"\/proc\/mounts|\/proc\/.*\/mounts|\/proc\/.*\/mountinfo",
              "permissions": [
                "r"
              ]
            }
          ],
        "testcases": [
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/mounts",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/self/mountinfo",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/self/task/8/mounts",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
        ]
      },
      "mitigate-host-ip-leak": {
        "rules": [
          {
            "path_regex": r"\/proc\/net\/arp|\/proc\/.*\/net\/arp",
            "permissions": [
              "r"
            ]
          }
        ],
        "testcases": [
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/net/arp",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/1/net/arp",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/1/task/1/net/arp",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/thread-self/net/arp",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/1/root/proc/net/arp",
                "permissions": [
                    "r",
                ]
              }
            ]
          },
          {
            "conflict": False,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/proc/1/root/proc/net/arp",
                "permissions": [
                    "a",
                ]
              }
            ]
          },
        ]
      },
      "cgroups-lxcfs-escape-mitigation": {
        "rules": [
          {
            "path_regex": r"\/release_agent$|\/devices\/devices.allow$|\/devices\/.*\/devices.allow$|\/devices\/cgroup.procs$|\/devices\/.*\/cgroup.procs$|\/devices\/tasks$|\/devices\/.*\/tasks$",
            "permissions": [
              "w",
              "a"
            ]
          }
        ],
        "testcases": [
          {
            "conflict": False,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/sys/fs/cgroup/devices/release_agent",
                "permissions": [
                    "r",
                    "l",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/sys/fs/cgroup/memory/release_agent",
                "permissions": [
                    "w",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/sys/fs/cgroup/devices/kubepods/besteffort/pod41f2ecf7-771c-4e79-bd68-3112fe5bff59/devices.allow",
                "permissions": [
                    "w",
                ]
              }
            ]
          },
          {
            "conflict": True,
            "files": [
              {
                "oldPath": "",
                "owner": True,
                "path": "/sys/fs/cgroup/devices/kubepods/besteffort/pod41f2ecf7-771c-4e79-bd68-3112fe5bff59/111/tasks",
                "permissions": [
                    "w",
                ]
              }
            ]
          },
        ]
      }
    }
    
    for key, value in data.items():
      print("------- %s -------" % key)
      for index, testcase in enumerate(value["testcases"]):
        print("Run testcase %d" % index)
        self.assertEqual(files_conflict_with_rule(value["rules"], testcase["files"]), testcase["conflict"])

if __name__ == '__main__':
    unittest.main()
