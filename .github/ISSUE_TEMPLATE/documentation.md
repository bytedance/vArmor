name: "Enhancement: Documentation"
description: Recommend an enhancement to the vArmor documentation and website.
title: "[Enhancement] "
labels: ["enhancement"]
body:
  - type: markdown
    attributes:
      value: |
        What would you like to see added to the documentation or website?
  - type: textarea
    id: description
    attributes:
      label: Description
      description: Describe what enhancement you'd like to see.
      # placeholder: Tell us what you see!
      # value: ""
    validations:
      required: true