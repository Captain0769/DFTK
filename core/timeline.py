from datetime import date, datetime, timezone


def sort_events(events):
    """Sort mixed forensic events newest first; undated events remain at the end."""
    return sorted(events, key=_sort_key, reverse=True)


def filter_events(
    events,
    query="",
    event_type="All event types",
    case_id=None,
    start_date=None,
    end_date=None,
):
    """Filter normalized timeline events without mutating the supplied collection."""
    search = query.strip().casefold()
    selected_type = event_type.casefold()
    filtered = []
    for event in events:
        if selected_type != "all event types" and str(
            event.get("event_type", "")
        ).casefold() != selected_type:
            continue
        if case_id is not None and event.get("case_id") != case_id:
            continue
        if search and not any(
            search in str(event.get(key) or "").casefold()
            for key in ("timestamp", "event_type", "subject", "details", "case_name")
        ):
            continue
        event_date = _event_date(event.get("timestamp"))
        if start_date is not None and (
            event_date is None or event_date < _as_date(start_date)
        ):
            continue
        if end_date is not None and (
            event_date is None or event_date > _as_date(end_date)
        ):
            continue
        filtered.append(event)
    return filtered


def _sort_key(event):
    parsed = _parse_timestamp(event.get("timestamp"))
    if parsed is None:
        return False, datetime.min.replace(tzinfo=timezone.utc)
    return True, parsed


def _event_date(value):
    parsed = _parse_timestamp(value)
    return parsed.date() if parsed is not None else None


def _parse_timestamp(value):
    if not value:
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
        for timestamp_format in (
            "%Y/%m/%d",
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S.%f",
        ):
            try:
                parsed = datetime.strptime(text, timestamp_format)
                break
            except ValueError:
                continue
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _as_date(value):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))
