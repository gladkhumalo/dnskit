"""Test doubles for dnspython, so the test suite never touches the network."""

from collections.abc import Callable, Iterator, Sequence
from types import SimpleNamespace

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset


class FakeAnswer:
    def __init__(self, values: list[str], ttl: int) -> None:
        self.rrset = SimpleNamespace(ttl=ttl)
        self._rdata = [SimpleNamespace(to_text=lambda v=v: v) for v in values]

    def __iter__(self) -> Iterator[SimpleNamespace]:
        return iter(self._rdata)


Responses = dict[str | tuple[str, str], FakeAnswer | Exception]


class FakeResolver:
    """Answers from `responses`, keyed by (name, rtype) or just rtype; else raises NoAnswer."""

    def __init__(self, responses: Responses, queried: list[tuple[str, str]]) -> None:
        self.responses = responses
        self.queried = queried

    def resolve(self, name: str, rtype: str) -> FakeAnswer:
        self.queried.append((name, rtype))
        response = self.responses.get((name, rtype)) or self.responses.get(
            rtype, dns.resolver.NoAnswer()
        )
        if isinstance(response, Exception):
            raise response
        return response


def no_nameservers(*reasons: object) -> dns.resolver.NoNameservers:
    """Build the NoNameservers dnspython raises, with one error entry per nameserver.

    Each reason is an exception or rcode text (e.g. "SERVFAIL"), as dnspython records them.
    """
    errors = [(f"192.0.2.{i}", False, 53, reason, None) for i, reason in enumerate(reasons, 1)]
    request = dns.message.make_query("example.com", "A")
    return dns.resolver.NoNameservers(request=request, errors=errors)


# --- Raw DNS messages, for code that sends queries itself (trace, dnssec) ------------------


def rrset(name: str, rtype: str, *values: str, ttl: int = 300) -> dns.rrset.RRset:
    return dns.rrset.from_text(name, ttl, "IN", rtype, *values)


def reply(
    query: dns.message.Message,
    *,
    answer: Sequence[dns.rrset.RRset] = (),
    authority: Sequence[dns.rrset.RRset] = (),
    additional: Sequence[dns.rrset.RRset] = (),
    rcode: str = "NOERROR",
    aa: bool = False,
) -> dns.message.Message:
    """A reply to `query`, built the way a real server's would be parsed."""
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.from_text(rcode))
    if aa:
        response.flags |= dns.flags.AA
    response.answer.extend(answer)
    response.authority.extend(authority)
    response.additional.extend(additional)
    return response


Handler = Callable[[dns.message.Message], "dns.message.Message | Exception"]


class FakeNetwork:
    """Stands in for a module's `_send(query, address, timeout)`.

    `handlers` maps a server address to a function from query to reply (or an exception to
    raise). An address without a handler times out. `sent` records (address, name, rtype).
    """

    def __init__(self) -> None:
        self.handlers: dict[str, Handler] = {}
        self.sent: list[tuple[str, str, str]] = []

    def __call__(
        self, query: dns.message.Message, address: str, timeout: float
    ) -> dns.message.Message:
        question = query.question[0]
        self.sent.append((address, question.name.to_text(), dns.rdatatype.to_text(question.rdtype)))
        handler = self.handlers.get(address)
        if handler is None:
            raise dns.exception.Timeout
        result = handler(query)
        if isinstance(result, Exception):
            raise result
        return result


def question(query: dns.message.Message) -> tuple[str, str]:
    """The (name, rtype) a query asks for."""
    q = query.question[0]
    return q.name.to_text(), dns.rdatatype.to_text(q.rdtype)
