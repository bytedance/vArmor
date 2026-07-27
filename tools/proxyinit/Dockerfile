FROM alpine:latest

# iptables provides the nft-backed binaries (iptables/ip6tables -> nft).
# iptables-legacy provides the legacy-backed binaries (iptables-legacy /
# ip6tables-legacy). Both backends are installed so the proxy-init script
# can pick the one already in use in the target Pod netns at runtime.
RUN apk add --no-cache iptables iptables-legacy

# varmor-choose-backend inspects the current netns and prints which iptables
# backend (legacy or nft) the injected rules should use. It is invoked by the
# proxy-init scripts in internal/webhooks/mutation.go and
# internal/policy/update.go.
COPY tools/proxyinit/varmor-choose-backend /usr/local/bin/varmor-choose-backend
RUN chmod +x /usr/local/bin/varmor-choose-backend
