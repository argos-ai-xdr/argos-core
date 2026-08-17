"""transparency_log: registro append-only local con hash-chain real
(ADR-023, ADR-017 Fase J; prompt maestro de arquitectura objetivo,
"APPEND-ONLY TRANSPARENCY LOG"). CLAIM-010 de `argos-control/assurance/
argos-assurance.yaml` — cierra ese `NOT_SUPPORTED` en el ámbito local.

**LOGICALLY_APPEND_ONLY / TAMPER_EVIDENT, NO "IMMUTABLE".** `TransparencyLog`
no expone ningún método de borrado o reescritura — la única API pública
es `append()`. Pero el backend real hoy es una lista en memoria (y,
opcionalmente, un archivo JSONL en disco): quien tenga acceso directo al
proceso Python o al archivo PUEDE editarlo. Lo que este módulo garantiza
no es que la edición sea imposible, sino que sea **detectable**:
`verify_chain()` recomputa cada `entry_hash` de forma independiente y
comprueba `entry[n].previous_entry_hash == entry[n-1].entry_hash` — una
edición histórica rompe la cadena a partir de ese punto, sin excepción.
Esto es explícitamente distinto de un almacenamiento WORM real
(object-lock de Ceph RGW, un Transparency Log externo tipo Sigstore) —
ninguno de los dos existe en este proyecto (ARG-002, BLOCKED_EXTERNAL).

Distinto de `argos-smartops/api/audit.py::AuditLog`: ese también evita
exponer borrado/modificación, pero no encadena hashes (no es
tamper-evident, solo "sin API de borrado") y solo cubre acciones de
operador dentro de ese servicio — no promoción/revocación de
componentes de IA/política/modelo a nivel de plataforma.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib

from argos_envelope import new_id_prefixed, utc_now_iso

GENESIS_HASH = "sha256:" + "0" * 64

#: Solo eventos que este sistema puede producir de verdad hoy.
#: COMPONENT_PROMOTED/COMPONENT_REVOKED quedan fuera a propósito: no
#: existe ningún flujo de promoción/revocación real todavía
#: (`argos-control/ai-governance/ai-component-registry.yaml` documenta
#: que `deterministic-fallback-engine` nunca pasó por un proceso formal
#: de promoción) -- añadirlos aquí sería registrar un evento que nadie
#: emite de verdad.
VALID_EVENT_TYPES = frozenset(
    {
        "EVIDENCE_ROOT_CREATED",
        "EVIDENCE_ROOT_VERIFIED",
        "ACTION_EXECUTED",
        "ACTION_VERIFIED",
        "ACTION_ROLLED_BACK",
    }
)


class UnknownEventType(ValueError):
    pass


class ReceiptNotFound(LookupError):
    pass


@dataclasses.dataclass(frozen=True)
class TransparencyEntry:
    sequence: int
    event_id: str
    event_type: str
    object_id: str
    object_hash: str
    previous_entry_hash: str
    timestamp: str
    run_id: str
    producer: str
    entry_hash: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> TransparencyEntry:
        return cls(**data)


def _fields_for_hash(entry: TransparencyEntry) -> dict:
    data = entry.to_dict()
    del data["entry_hash"]
    return data


def _compute_entry_hash(entry: TransparencyEntry) -> str:
    canonical = json.dumps(_fields_for_hash(entry), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclasses.dataclass(frozen=True)
class ChainVerificationResult:
    ok: bool
    broken_at_sequence: int | None
    detail: str


class TransparencyLog:
    """No es un dataclass a propósito: expone deliberadamente una única
    vía de mutación pública (`append`) -- un dataclass generaría además
    `__eq__`/`__repr__` sobre `_entries` que invitarían a tratarlo como
    un contenedor de datos ordinario en vez de como el punto de control
    que es."""

    def __init__(self, persist_path: pathlib.Path | None = None):
        self._entries: list[TransparencyEntry] = []
        self._persist_path = persist_path

    def append(self, *, event_type: str, object_id: str, object_hash: str, run_id: str, producer: str) -> TransparencyEntry:
        if event_type not in VALID_EVENT_TYPES:
            raise UnknownEventType(f"{event_type!r} no es un evento real soportado: {sorted(VALID_EVENT_TYPES)}")

        sequence = len(self._entries)
        previous_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        entry_without_hash = TransparencyEntry(
            sequence=sequence,
            event_id=new_id_prefixed("evtlog"),
            event_type=event_type,
            object_id=object_id,
            object_hash=object_hash,
            previous_entry_hash=previous_hash,
            timestamp=utc_now_iso(),
            run_id=run_id,
            producer=producer,
            entry_hash="",
        )
        entry = dataclasses.replace(entry_without_hash, entry_hash=_compute_entry_hash(entry_without_hash))
        self._entries.append(entry)
        if self._persist_path is not None:
            with self._persist_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n")
        return entry

    def entries(self) -> tuple[TransparencyEntry, ...]:
        return tuple(self._entries)  # copia inmutable -- modificar el resultado no afecta al log

    def entries_for(self, object_id: str) -> tuple[TransparencyEntry, ...]:
        return tuple(e for e in self._entries if e.object_id == object_id)

    def verify_chain(self) -> ChainVerificationResult:
        previous_hash = GENESIS_HASH
        for entry in self._entries:
            if entry.previous_entry_hash != previous_hash:
                return ChainVerificationResult(
                    ok=False,
                    broken_at_sequence=entry.sequence,
                    detail=f"sequence {entry.sequence}: previous_entry_hash no coincide con el hash real de la entrada anterior",
                )
            recomputed = _compute_entry_hash(entry)
            if recomputed != entry.entry_hash:
                return ChainVerificationResult(
                    ok=False,
                    broken_at_sequence=entry.sequence,
                    detail=f"sequence {entry.sequence}: entry_hash no coincide con el contenido real de la entrada (mutación detectada)",
                )
            previous_hash = entry.entry_hash
        return ChainVerificationResult(ok=True, broken_at_sequence=None, detail="cadena íntegra")

    def issue_receipt(self, object_id: str) -> TransparencyReceipt:
        matches = self.entries_for(object_id)
        if not matches:
            raise ReceiptNotFound(f"ningún evento registrado para object_id={object_id!r}")
        entry = matches[-1]  # el más reciente si hay varios eventos para el mismo objeto
        return TransparencyReceipt(
            receipt_id=new_id_prefixed("rcpt"),
            object_id=entry.object_id,
            event_type=entry.event_type,
            sequence=entry.sequence,
            entry_hash=entry.entry_hash,
            previous_entry_hash=entry.previous_entry_hash,
            chain_length_at_issuance=len(self._entries),
            issued_at=utc_now_iso(),
        )


def load_log(path: pathlib.Path) -> TransparencyLog:
    """Reconstruye un TransparencyLog desde un archivo JSONL persistido
    con `append(persist_path=...)`. El log reconstruido comparte el
    mismo `verify_chain()` -- cargar de disco no es una vía para saltarse
    la comprobación de integridad."""
    log = TransparencyLog()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                log._entries.append(TransparencyEntry.from_dict(json.loads(line)))
    return log


@dataclasses.dataclass(frozen=True)
class TransparencyReceipt:
    receipt_id: str
    object_id: str
    event_type: str
    sequence: int
    entry_hash: str
    previous_entry_hash: str
    chain_length_at_issuance: int
    issued_at: str

    # No incluye ningún campo de firma criptográfica -- Sovereign Root of
    # Trust no existe (ARG-002/ARG-020, BLOCKED_EXTERNAL). Declarar uno
    # aquí sería fabricar una garantía que este sistema no puede dar hoy.


def verify_receipt(receipt: TransparencyReceipt, log: TransparencyLog) -> bool:
    """Comprueba que el log contiene de verdad la entrada que el receipt
    afirma, con el mismo entry_hash/previous_entry_hash/secuencia, Y que
    la cadena sigue siendo íntegra hasta ese punto -- un receipt válido
    sobre un log cuya historia fue mutada después no debe pasar."""
    entries = log.entries()
    if receipt.sequence >= len(entries):
        return False
    entry = entries[receipt.sequence]
    if entry.object_id != receipt.object_id or entry.entry_hash != receipt.entry_hash:
        return False
    if entry.previous_entry_hash != receipt.previous_entry_hash:
        return False
    chain_result = log.verify_chain()
    if chain_result.ok:
        return True
    # La cadena está rota, pero puede haberse roto DESPUÉS del punto que
    # este receipt certifica -- el receipt sigue siendo válido si la
    # ruptura ocurre en una secuencia posterior a la suya.
    return chain_result.broken_at_sequence is not None and chain_result.broken_at_sequence > receipt.sequence
