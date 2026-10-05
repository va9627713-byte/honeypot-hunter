# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security
vulnerability, please report it responsibly:

1. **Do not** create a public GitHub issue
2. Email us at: **security@honeypot-hunter.example.com**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
   - Your contact information

We will:
- Acknowledge receipt within 48 hours
- Provide a preliminary assessment within 5 business days
- Keep you informed of progress
- Credit you in the advisory (if desired)

## Security Features

### Network Security
- All listeners bind to localhost by default
- TLS support for all services (optional)
- mTLS for sensor-collector communication
- Rate limiting and anti-pollution controls
- No egress enforcement (operator responsibility)

### Data Protection
- Hash-chained JSONL logs (SHA-256 chained)
- Credential retention modes: off / hashed / full
- No sample execution in artifact analysis
- Credential redaction by default
- Hash-chained log verification at startup

### Authentication & Authorization
- API key, OIDC, LDAP, Basic auth support
- API keys with role-based access
- mTLS for sensor-collector communication
- Session management with configurable timeouts
- Rate limiting on API endpoints

### Deployment Security
- Container services run as non-root
- Read-only root filesystem for containers
- No new privileges
- All capabilities dropped
- Resource limits (CPU, memory, PIDs)
- Network isolation via user-defined bridges

## Secure Deployment Checklist

Before exposing to untrusted networks:

- [ ] Change default ports from unprivileged to standard (22, 23, 21, 80)
- [ ] Enable TLS with valid certificates
- [ ] Configure `bind_host` appropriately
- [ ] Set up firewall egress restrictions
- [ ] Configure credential retention policy
- [ ] Set up alert webhook with HTTPS
- [ ] Enable GeoIP with licensed database
- [ ] Configure data retention and purge schedule
- [ ] Set up log monitoring and alerting
- [ ] Verify network isolation and egress controls
- [ ] Test with attack simulator

## Known Limitations

- **Not a certified security product** - this is a research/prototype tool
- **No egress enforcement** - operators must enforce at host/cloud level
- **Dashboard has no authentication** - never expose to untrusted networks
- **Credential retention `hashed`** - weak passwords still guessable offline
- **Local LLM** - only loopback, model output never executed but may influence logs
- **Anti-escape heuristics** - alerting only, not proof of escape
- **No automated blocking** - auto-block only populates local denylist

## Threat Model

### In Scope
- Deception and monitoring of unsolicited attacks
- Credential harvesting observation
- Exploit attempt detection
- Command/control observation
- Malware/sample triage (static only)
- Attacker behavior profiling

### Out of Scope
- Active defense or counter-attack
- Sample execution/detonation
- Automated infrastructure blocking
- Legal attribution or law enforcement integration
- Real-time threat intelligence sharing (operator responsibility)

## Compliance Considerations

- **GDPR**: IP addresses are personal data; configure retention/purge
- **Data minimization**: Only collect what's needed for threat intelligence
- **Access control**: Restrict log access to authorized personnel
- **Retention**: Default 90 days for raw events, configurable
- **Right to erasure**: Implement purge for specific IPs if required

## Responsible Disclosure Timeline

| Phase | Timeline |
|-------|----------|
| Acknowledgment | 48 hours |
| Preliminary assessment | 5 business days |
| Fix development | Based on severity |
| Coordinated disclosure | 90 days (negotiable) |
| Public advisory | After fix released |

## Contact

Security Team: security@honeypot-hunter.example.com
PGP Key: Available on request

---

*This security policy is a living document and will be updated as the project evolves.*