// Reject URLs, shell syntax and host:port pairs: the server accepts a single
// host and numeric port, never a command line. IPv6 is entered without brackets.
export function validProbeHost(host: string): boolean {
  if (!host || host.length > 253 || /[\s/\\@?#[\]]/.test(host)) return false
  if (host.includes(':')) {
    try {
      return new URL(`http://[${host}]/`).hostname.startsWith('[')
    } catch {
      return false
    }
  }
  // Mirrors the server: when every label is a number in some inet_aton base
  // (decimal, leading-0 octal, 0x hex), resolvers may read it as an address,
  // so only a canonical dotted quad is allowed.
  if (host.replace(/\.$/, '').split('.').every((part) => /^(\d*|0x[\da-f]*)$/i.test(part))) {
    const parts = host.split('.')
    return parts.length === 4 && parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)
  }
  return host.replace(/\.$/, '').split('.').every((part) =>
    part.length <= 63 && /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(part)
  )
}

export function validProbeNamespace(namespace: string): boolean {
  return namespace.length <= 63 && /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/.test(namespace)
}

export function validProbePort(port: string): boolean {
  return /^\d{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65535
}
