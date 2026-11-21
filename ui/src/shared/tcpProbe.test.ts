import { describe, expect, it } from 'vitest'
import { validProbeHost, validProbeNamespace, validProbePort } from './tcpProbe'

describe('finite TCP inputs', () => {
  it('accepts DNS names and IPv4/IPv6 literals', () => {
    for (const host of ['postgres', 'db.postgres.svc.cluster.local', 'example.com.', '10.0.0.1', '::1', '2001:db8::1']) {
      expect(validProbeHost(host), host).toBe(true)
    }
  })
  it('rejects command syntax, URLs, invalid IPs and embedded ports', () => {
    for (const host of ['', 'db:5432', 'https://db', 'db;id', '-v', 'db host', '999.0.0.1', '01.2.3.4', '[::1]', '::wrong', 'db/path', 'a'.repeat(64), '.']) {
      expect(validProbeHost(host), host).toBe(false)
    }
  })
  it('requires one namespace and an integer port in range', () => {
    expect(validProbeNamespace('my-app')).toBe(true)
    for (const ns of ['', 'ALL', '-app', 'a'.repeat(64)]) expect(validProbeNamespace(ns)).toBe(false)
    for (const port of ['1', '5432', '65535']) expect(validProbePort(port)).toBe(true)
    for (const port of ['', '0', '65536', '1.5', '-1', '1e3', ' 80']) expect(validProbePort(port)).toBe(false)
  })
})
