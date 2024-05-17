# owl - full control of your mail

## mail flow

### stage 1

Envelope/Headers

- public
- tcp 25
- ehlo
  - store sni, ehlo and ip
  - rbl and ehlo dns checks
  - policy by sni (tenant/domain/user)
- starttls
  - store the version/signature
- mail from
  - sender spf checks
- rcpt to
  - destination verification
  - tenant rules
  - user rules
  - reject with no quarantine
- data
  - stream original headers + body to queue storage (tenant/user customizable)
  - store metadata
  - initiate stage 2
- reject or return traceable queue id

### stage 2

Queue/Routing

- 


# delivery transports