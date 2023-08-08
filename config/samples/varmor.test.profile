abi <abi/3.0>,

profile varmor.test.profile {
  file,
  network,
  deny file /etc/passwd r,

  deny network icmp,
  #capability,
  #deny capability net_bind_service,
  #capability net_raw,
  #signal send,
}
