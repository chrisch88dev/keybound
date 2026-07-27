# Storage

Keybound does not ship a database adapter because apps already have different storage stacks. The required contract is small:

```ts
interface KeyboundChallengeStore {
  get(challengeId: string): Promise<KeyboundChallengeRecord | null>;
  consume(challengeId: string, expectedDigest: string): Promise<boolean>;
}
```

`consume` must be atomic. Two valid requests racing the same challenge must produce one success and one replay denial.

## PostgreSQL

Table:

```sql
create table keybound_challenges (
  id text primary key,
  digest text not null,
  expires_at bigint not null
);

create index keybound_challenges_expires_at_idx
  on keybound_challenges (expires_at);
```

Insert:

```sql
insert into keybound_challenges (id, digest, expires_at)
values ($1, $2, $3);
```

Get:

```sql
select id, digest, expires_at
from keybound_challenges
where id = $1;
```

Atomic consume:

```sql
delete from keybound_challenges
where id = $1
  and digest = $2
returning id;
```

Return `true` if one row is returned. Return `false` otherwise.

Cleanup:

```sql
delete from keybound_challenges
where expires_at < $1;
```

## MySQL

Atomic consume:

```sql
delete from keybound_challenges
where id = ?
  and digest = ?
limit 1;
```

Return `true` when `affectedRows === 1`.

## Redis

Store each challenge by ID with a short TTL:

```text
SET keybound:challenge:<id> <digest> PX <ttl_ms> NX
```

Atomic consume with Lua:

```lua
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end

return 0
```

Return `true` when the script returns `1`.

## Device Records

Challenge storage is separate from device storage. Store enrolled devices with your user or session state:

```text
user_id
session_id or session_family_id
device_id
public_key
created_at
last_seen_at
revoked_at
```

The public key must come from this record during challenge issue and proof verification.

Do not accept a public key from the proof request body as enrolled state.

## Common Mistakes

Avoid these:

```text
read challenge, then delete it later without a condition
verify against a public key sent by the attacker
auto-enroll a new device from only a session cookie
reuse one challenge for several actions
store raw challenges when a digest is enough
skip expiry cleanup
```
