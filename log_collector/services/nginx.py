import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit


LOG_PATTERN = re.compile(
    r'^(?P<ip>[^ ]+) [^ ]+ [^ ]+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)


@dataclass(frozen=True)
class ParsedNginxLine:
    timestamp: datetime
    ip_address: str
    method: str
    path: str
    query_string: str
    protocol: str
    status_code: int
    bytes_sent: int | None
    referrer: str
    user_agent: str
    raw_line_hash: str


def parse_nginx_line(line):
    match = LOG_PATTERN.match(line.rstrip("\r\n"))
    if not match:
        return None
    request_parts = match.group("request").split(" ", 2)
    if len(request_parts) != 3:
        return None
    try:
        timestamp = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z")
        request_url = urlsplit(request_parts[1])
        return ParsedNginxLine(
            timestamp=timestamp,
            ip_address=match.group("ip"),
            method=request_parts[0],
            path=request_url.path or "/",
            query_string=request_url.query,
            protocol=request_parts[2],
            status_code=int(match.group("status")),
            bytes_sent=None if match.group("bytes") == "-" else int(match.group("bytes")),
            referrer="" if match.group("referrer") == "-" else match.group("referrer"),
            user_agent="" if match.group("user_agent") == "-" else match.group("user_agent"),
            raw_line_hash=hashlib.sha256(line.rstrip("\r\n").encode("utf-8")).hexdigest(),
        )
    except (TypeError, ValueError):
        return None
