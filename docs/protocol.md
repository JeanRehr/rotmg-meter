# Protocol evidence for combat metrics

This document records protocol facts that can guide future meter work. It does
not define combat calculations. Packet IDs must be interpreted together with
their direction: the registry resolves incoming and outgoing packets
separately, so an ID alone is not a packet identity.

## Evidence snapshot

The reference is the project `realmlib`.
Its `docs/INDEX.md` identifies `docs/FULL_PROTOCOL_AUDIT_2026-08-01.md` as the
superseding current-registry/native audit. Packet direction and IDs below are
from `src/packet-registry.ts` and `protocol/exalt-current.json`; body fields
are from the packet classes under `src/packets/`. These paths refer to the
`realmlib` repository and are not paths within this project.

The registry is evidence for packet naming, direction, and ID assignment. The
packet classes document RealmLib's current wire layouts. These sources do not
by themselves establish the server's complete combat semantics or guarantee
that every gameplay event is represented by a dedicated message.

## Relevant packets

| Direction | ID | Registry name | Fields or role supported by the reference | Confidence and limits |
| --- | ---: | --- | --- | --- |
| Server to client | 75 | `DAMAGE` | Target object ID; status-effect list; damage amount; info/flags byte; bullet ID; projectile-owner object ID. | Registry and packet layout are explicit. Described as damage reported to the player for other players and enemies. Does not by itself prove that the owner is the player's character or that the event should count as damage dealt by the local player. |
| Server to client | 166 | `DAMAGE_WITH_EFFECT` | A `DAMAGE`-shaped body followed by an effect ID and float value. | The current packet class and audit support the extended layout. Audited samples establish specific effect behavior (including Stasis duration), not a general healing meaning for the value. |
| Server to client | 46 | `DEATH` | Account ID, character ID, cause-of-death text, an unknown integer, fame/account progression fields, fame bonuses, and packed character stats. | The packet class labels it as a player death notification. It is evidence of a death event and reported cause, not a complete timeline of preceding damage. |
| Server to client | 42 | `UPDATE` | View position and level type, then visible tiles, newly visible objects, and object IDs dropped from view. | The packet class describes visibility updates. It can supply world/object state, but the field layout alone does not establish health-change or healing attribution. |
| Server to client | 45 | `RECONNECT` | New connection name/host/port and parameters for the next `HELLO`. | A connection transition, not a combat event. Do not log or publish reconnect keys or capture-derived connection values. |
| Client to server | 25 | `ENEMYHIT` | Client time, bullet ID, shooter ID, target ID, kill claim, and a trailing object ID. | The packet class describes a client hit report. It is a hit claim, not confirmation of server-accepted damage or its amount. |
| Client to server | 90 | `PLAYERHIT` | Bullet ID and the object ID of the enemy that hit the player. | The packet class describes a client report that the player was hit. It does not prove the server's resulting damage amount. |

The outgoing hit packets are direction-sensitive requests or claims. For
damage totals, prefer server-to-client damage reports when their target and
owner can be attributed with sufficient confidence; do not treat a client hit
claim as a confirmed damage event.

## Healing evidence and limits

No explicit healing packet was found in the incoming packet registry or the
current incoming packet definitions reviewed for this document. This is a
bounded search result, not proof that healing is absent from the protocol.
Healing-related changes may be represented through broader state updates or
other effects whose semantics still need evidence.

The reviewed definitions do not establish a healing event, amount restored,
overhealing, or the source of a heal. Do not report those as measured values
until a packet meaning and attribution method are supported by current
protocol evidence and suitable captures. Any future inference should be
labeled as an inference and should state its assumptions.

## Transport and interpretation limits

These packet IDs and fields apply only after correctly identifying the TCP
stream direction and decoding the application's framing. TCP segments are not
application messages. The current Rust transport layer extracts TCP segments
and can reassemble a direction when given a payload origin; it does not yet
infer origins, recover missing capture bytes, track connection reuse, or decode
RotMG application messages.

The local captures described in the project prompt are investigation guides,
not verified semantic evidence. Keep them local and do not copy their raw
payloads, addresses, credentials, or unredacted contents into this document.
