"""Historical identity resolution module.

Reconstructs user identity state across time using identity snapshots and audit logs.
Adheres strictly to the temporal cutoff (audit_at):
- Normalizes email casing and whitespace.
- Links current and historical identifiers to stable user IDs.
- Excludes identity changes occurring after audit_at.
- Guards against false merges (never merges on name similarity or ambiguous identifiers).
- Surfaces explicit ambiguity when multiple users claim the same identifier.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

try:
    from .models import UserIdentity, UserAuditLogEntry
except (ImportError, ValueError):
    from models import UserIdentity, UserAuditLogEntry


def normalize_email(email: Optional[str]) -> str:
    """Normalize email address by stripping surrounding whitespace and converting to lowercase."""
    if not email:
        return ""
    return email.strip().lower()


def normalize_phone(phone: Optional[str]) -> str:
    """Normalize phone string by stripping whitespace."""
    if not phone:
        return ""
    return " ".join(phone.strip().split())


@dataclass
class FieldInterval:
    """Represents a time interval during which a field held a specific value."""
    value: str
    start_time: str  # ISO-8601 or '-infinity'
    end_time: str    # ISO-8601 or '+infinity'


@dataclass
class ResolvedIdentity:
    """Identity profile resolved as of a specific audit_at cutoff."""
    user_id: str
    name: str
    primary_email_at_cutoff: str
    historical_emails_at_cutoff: Set[str] = field(default_factory=set)
    all_emails_at_cutoff: Set[str] = field(default_factory=set)
    primary_phone_at_cutoff: str = ""
    historical_phones_at_cutoff: Set[str] = field(default_factory=set)
    all_phones_at_cutoff: Set[str] = field(default_factory=set)
    primary_email_hash_at_cutoff: str = ""
    historical_email_hashes_at_cutoff: Set[str] = field(default_factory=set)
    all_email_hashes_at_cutoff: Set[str] = field(default_factory=set)
    is_matched: bool = True
    is_ambiguous: bool = False
    ambiguity_reason: Optional[str] = None


class UserTimeline:
    """Maintains the full chronological evolution of a single user's identifiers."""

    def __init__(self, identity: UserIdentity):
        self.user_id = identity.user_id
        self.name = identity.name
        self.snapshot_updated_at = identity.updated_at
        self.snapshot_email = normalize_email(identity.email)
        self.snapshot_phone = normalize_phone(identity.phone)
        self.snapshot_email_hash = identity.email_hash.strip().lower()

        # Raw audit events for this user
        self.audit_events: List[UserAuditLogEntry] = []

        # Reconstructed intervals per field
        self._email_intervals: Optional[List[FieldInterval]] = None
        self._phone_intervals: Optional[List[FieldInterval]] = None
        self._email_hash_intervals: Optional[List[FieldInterval]] = None

    def add_audit_event(self, entry: UserAuditLogEntry):
        """Register an audit log entry for this user."""
        self.audit_events.append(entry)
        # Invalidate cached intervals
        self._email_intervals = None
        self._phone_intervals = None
        self._email_hash_intervals = None

    def _build_intervals_for_field(
        self, field_name: str, snapshot_value: str
    ) -> List[FieldInterval]:
        """Build ordered intervals for a specific field based on audit events and snapshot."""
        events = [e for e in self.audit_events if e.field_name == field_name]
        if not events:
            return [FieldInterval(value=snapshot_value, start_time="-infinity", end_time="+infinity")]

        # Sort events chronologically
        events.sort(key=lambda e: e.event_time)

        intervals: List[FieldInterval] = []
        # First interval from beginning of time until the first change
        first_event = events[0]
        first_val = first_event.old_value
        if field_name == "email":
            first_val = normalize_email(first_val)
        elif field_name == "phone":
            first_val = normalize_phone(first_val)
        elif field_name == "email_hash":
            first_val = first_val.strip().lower()

        intervals.append(FieldInterval(value=first_val, start_time="-infinity", end_time=first_event.event_time))

        for i, ev in enumerate(events):
            start = ev.event_time
            end = events[i + 1].event_time if i + 1 < len(events) else "+infinity"
            val = ev.new_value
            if field_name == "email":
                val = normalize_email(val)
            elif field_name == "phone":
                val = normalize_phone(val)
            elif field_name == "email_hash":
                val = val.strip().lower()
            intervals.append(FieldInterval(value=val, start_time=start, end_time=end))

        return intervals

    def get_email_intervals(self) -> List[FieldInterval]:
        if self._email_intervals is None:
            self._email_intervals = self._build_intervals_for_field("email", self.snapshot_email)
        return self._email_intervals

    def get_phone_intervals(self) -> List[FieldInterval]:
        if self._phone_intervals is None:
            self._phone_intervals = self._build_intervals_for_field("phone", self.snapshot_phone)
        return self._phone_intervals

    def get_email_hash_intervals(self) -> List[FieldInterval]:
        if self._email_hash_intervals is None:
            self._email_hash_intervals = self._build_intervals_for_field("email_hash", self.snapshot_email_hash)
        return self._email_hash_intervals

    def resolve_at(self, cutoff_time: str) -> ResolvedIdentity:
        """Resolve this user's identifiers as of cutoff_time.

        Only considers changes that occurred at or before cutoff_time.
        """
        email_intervals = self.get_email_intervals()
        phone_intervals = self.get_phone_intervals()
        hash_intervals = self.get_email_hash_intervals()

        def _resolve_field(intervals: List[FieldInterval]) -> Tuple[str, Set[str], Set[str]]:
            # Find interval active at cutoff_time
            active_val = ""
            historical_vals = set()
            all_vals = set()

            for interval in intervals:
                # Does interval start at or before cutoff?
                # start_time == '-infinity' is always <= cutoff_time
                starts_before_cutoff = (interval.start_time == "-infinity" or interval.start_time <= cutoff_time)
                if not starts_before_cutoff:
                    # This interval started in the future relative to cutoff! Skip.
                    continue

                all_vals.add(interval.value)

                # Is this interval active at cutoff_time?
                # Active if start_time <= cutoff_time < end_time (or end_time == '+infinity' or cutoff_time <= end_time)
                # Note: If cutoff_time == end_time, the transition occurred at end_time.
                ends_after_cutoff = (interval.end_time == "+infinity" or cutoff_time < interval.end_time)
                if ends_after_cutoff:
                    active_val = interval.value

            # Historical values are all values known up to cutoff minus the currently active one
            for v in all_vals:
                if v != active_val:
                    historical_vals.add(v)

            # Fallback if no interval matched active
            if not active_val and intervals:
                # Use the latest interval that started before cutoff
                valid_intervals = [i for i in intervals if i.start_time == "-infinity" or i.start_time <= cutoff_time]
                if valid_intervals:
                    active_val = valid_intervals[-1].value
                    historical_vals.discard(active_val)

            return active_val, historical_vals, all_vals

        active_email, hist_emails, all_emails = _resolve_field(email_intervals)
        active_phone, hist_phones, all_phones = _resolve_field(phone_intervals)
        active_hash, hist_hashes, all_hashes = _resolve_field(hash_intervals)

        return ResolvedIdentity(
            user_id=self.user_id,
            name=self.name,
            primary_email_at_cutoff=active_email,
            historical_emails_at_cutoff=hist_emails,
            all_emails_at_cutoff=all_emails,
            primary_phone_at_cutoff=active_phone,
            historical_phones_at_cutoff=hist_phones,
            all_phones_at_cutoff=all_phones,
            primary_email_hash_at_cutoff=active_hash,
            historical_email_hashes_at_cutoff=hist_hashes,
            all_email_hashes_at_cutoff=all_hashes,
            is_matched=True,
            is_ambiguous=False,
        )


class IdentityResolver:
    """Manages identity resolution across all users."""

    def __init__(self, identities: List[UserIdentity], audit_log: List[UserAuditLogEntry]):
        self.timelines: Dict[str, UserTimeline] = {}
        self._user_ids_by_normalized_name: Dict[str, Set[str]] = {}

        # Initialize timelines
        for identity in identities:
            uid = identity.user_id
            if uid in self.timelines:
                # Duplicate user_id in identities table
                pass
            timeline = UserTimeline(identity)
            self.timelines[uid] = timeline

            norm_name = identity.name.strip().lower()
            self._user_ids_by_normalized_name.setdefault(norm_name, set()).add(uid)

        # Distribute audit events to user timelines
        for entry in audit_log:
            uid = entry.user_id
            if uid in self.timelines:
                self.timelines[uid].add_audit_event(entry)

    def find_user_by_email_at(self, email: str, cutoff_time: str) -> ResolvedIdentity:
        """Find the unique user matching an email at cutoff_time.

        Returns:
            ResolvedIdentity with is_matched=True if uniquely resolved.
            ResolvedIdentity with is_matched=False or is_ambiguous=True if not found or ambiguous.
        """
        norm_email = normalize_email(email)
        if not norm_email:
            return ResolvedIdentity(
                user_id="",
                name="",
                primary_email_at_cutoff="",
                is_matched=False,
                is_ambiguous=False,
                ambiguity_reason="empty_email"
            )

        matching_users: List[Tuple[str, ResolvedIdentity]] = []

        for uid, timeline in self.timelines.items():
            resolved = timeline.resolve_at(cutoff_time)
            if norm_email in resolved.all_emails_at_cutoff:
                matching_users.append((uid, resolved))

        if not matching_users:
            # Check if this email matches in the future (after cutoff)
            future_matches = []
            for uid, timeline in self.timelines.items():
                for interval in timeline.get_email_intervals():
                    if interval.value == norm_email and interval.start_time > cutoff_time:
                        future_matches.append(uid)

            reason = "email_not_found"
            if future_matches:
                reason = "email_change_occurred_after_cutoff"

            return ResolvedIdentity(
                user_id="",
                name="",
                primary_email_at_cutoff=norm_email,
                is_matched=False,
                is_ambiguous=False,
                ambiguity_reason=reason
            )

        if len(matching_users) > 1:
            # Multiple distinct users share this email as of cutoff!
            # Do NOT merge them!
            matched_uids = [u[0] for u in matching_users]
            return ResolvedIdentity(
                user_id="",
                name="",
                primary_email_at_cutoff=norm_email,
                is_matched=False,
                is_ambiguous=True,
                ambiguity_reason=f"duplicate_identity_conflict: {matched_uids}"
            )

        return matching_users[0][1]

    def resolve_user_at(self, user_id: str, cutoff_time: str) -> Optional[ResolvedIdentity]:
        """Resolve a specific user_id as of cutoff_time."""
        if user_id not in self.timelines:
            return None
        return self.timelines[user_id].resolve_at(cutoff_time)
