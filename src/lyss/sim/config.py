# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Running configuration of a simulated switch: parsed into top-level entries (a line plus its
indented children), rendered back in the platform's own layout, and changed by configuration
commands the way the real CLI does (add, replace a single-valued setting, remove with "no")."""

import re
from dataclasses import dataclass, field


@dataclass
class Entry:
    line: str
    children: list[str] = field(default_factory=list)
    block: bool = False                             # Cisco SB / HP: block closed by "exit"
    text: list[str] = field(default_factory=list)   # Cisco SB multi-line banner body


# configuration commands that open a sub-mode, and the prompt suffix of that sub-mode
SUBMODES = {
    "cisco_ios": [
        (r"^interface\s", "config-if"), (r"^line\s", "config-line"),
        (r"^ip access-list standard\s", "config-std-nacl"), (r"^ip access-list extended\s", "config-ext-nacl"),
        (r"^radius server\s", "config-radius-server"), (r"^aaa group server\s", "config-sg-radius"),
        (r"^router\s", "config-router"), (r"^vlan \d+$", "config-vlan"),
    ],
    "cisco_sb": [
        (r"^interface\s", "config-if"), (r"^line\s", "config-line"),
        (r"^management access-list\s", "config-macl"), (r"^vlan database$", "config-vlan"),
    ],
    "hp_procurve": [(r"^vlan (\d+)$", "vlan-{0}"), (r"^interface (\S+)$", "eth-{0}")],
}

# settings that hold one value: a new value replaces the old line
SINGLE_VALUED = [
    r"^hostname\b", r"^ip ssh version\b", r"^banner (login|motd|exec)\b", r"^clock source\b",
    r"^console idle-timeout \d", r"^console idle-timeout serial-usb\b", r"^management-vlan\b",
    r"^enable (algorithm-type \S+ )?secret\b", r"^logging trap\b",
    # inside blocks
    r"^transport input\b", r"^exec-timeout\b", r"^access-class \S+ in\b", r"^switchport mode\b",
    r"^switchport access vlan\b", r"^ip address\b", r"^description\b", r"^name\b",
]

# features that are ON unless the configuration says "no ...": "no X" is written explicitly,
# and turning them back on only removes that line
DEFAULT_ON = {
    "cisco_ios": {"ip http server", "ip http secure-server"},
    "cisco_sb": {"ip telnet server", "ip http server"},
    "hp_procurve": {"telnet-server", "web-management plaintext"},
}


def parse(text: str) -> list[Entry]:
    entries: list[Entry] = []
    current: Entry | None = None
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i].rstrip()
        i += 1
        if not raw.strip():
            continue
        stripped = raw.strip()
        if raw[0] in " \t" and current is not None and stripped != "exit":
            current.children.append(stripped)
            continue
        if stripped == "exit":
            if current is not None:
                current.block = True
            current = None
            continue
        entry = Entry(stripped)
        m = re.match(r"^banner (login|motd|exec) (\S)$", stripped)
        if m:  # Cisco SB multi-line banner: body until the delimiter line
            while i < len(lines) and lines[i].strip() != m.group(2):
                entry.text.append(lines[i].rstrip())
                i += 1
            i += 1
        entries.append(entry)
        current = entry
    return entries


def render(entries: list[Entry], platform: str) -> str:
    indent = "   " if platform == "hp_procurve" else " "
    out = []
    for e in entries:
        out.append(e.line)
        if e.text:
            out += e.text + [e.line.split()[-1]]
        out += [indent + c for c in e.children]
        if e.block:
            out.append(indent + "exit" if platform == "hp_procurve" else "exit")
    return "\n".join(out) + "\n"


def submode(platform: str, command: str) -> str | None:
    """Prompt suffix if the command opens a sub-mode."""
    for pattern, name in SUBMODES[platform]:
        m = re.match(pattern, command, re.I)
        if m:
            return name.format(*m.groups())
    return None


def _same_setting(a: str, b: str) -> bool:
    return any(re.match(p, a) and re.match(p, b) for p in SINGLE_VALUED)


def apply(lines: list[str], command: str, platform: str) -> None:
    """Apply one configuration command to a list of lines (top-level lines or block children)."""
    command = re.sub(r"\s+", " ", command.strip())
    default_on = DEFAULT_ON[platform]
    if command.startswith(("no ", "default ")):
        target = command.split(" ", 1)[1]
        # "no snmp-server community public" also removes "snmp-server community public RO"
        lines[:] = [l for l in lines if not (l == target or l.startswith(target + " "))]
        if target in default_on and command.startswith("no ") and f"no {target}" not in lines:
            lines.append(f"no {target}")
        return
    lines[:] = [l for l in lines if l != f"no {command}" and not _same_setting(l, command)]
    if command in default_on:
        return  # back to the default: nothing is written
    if command not in lines:
        lines.append(command)


class RunningConfig:
    def __init__(self, text: str, platform: str):
        self.platform = platform
        self.entries = parse(text)

    def text(self) -> str:
        return render(self.entries, self.platform)

    def lines(self) -> list[str]:
        out = []
        for e in self.entries:
            out.append(e.line)
            out += e.children
        return out

    def top(self) -> list[str]:
        return [e.line for e in self.entries]

    def blocks(self, header: str) -> list[Entry]:
        pattern = re.compile(header, re.I)
        return [e for e in self.entries if pattern.search(e.line)]

    def find_block(self, header: str) -> Entry | None:
        h = re.sub(r"\s+", " ", header.strip()).lower()
        return next((e for e in self.entries if e.line.lower() == h), None)

    def open_block(self, header: str) -> Entry:
        """Sub-mode command: the existing block, or a new one."""
        found = self.find_block(header)
        if found:
            return found
        entry = Entry(re.sub(r"\s+", " ", header.strip()), block=self.platform != "cisco_ios")
        self._insert(entry)
        return entry

    def _insert(self, entry: Entry) -> None:
        # Cisco IOS keeps "end" last
        if self.entries and self.entries[-1].line == "end":
            self.entries.insert(len(self.entries) - 1, entry)
        else:
            self.entries.append(entry)

    def set_banner(self, kind: str, body: list[str], delimiter: str) -> None:
        self.entries = [e for e in self.entries if not re.match(rf"^banner {kind}\b", e.line)]
        if self.platform == "cisco_sb":
            self._insert(Entry(f"banner {kind} {delimiter}", text=body))
        elif self.platform == "hp_procurve":
            self._insert(Entry(f'banner {kind} "{" ".join(body)}"'))
        else:
            self._insert(Entry(f"banner {kind} ^C{chr(10).join(body)}^C"))

    def configure(self, block: Entry | None, command: str) -> None:
        """A configuration command at the global level (block None) or inside a block."""
        if block is not None:
            apply(block.children, command, self.platform)
            return
        cmd = re.sub(r"\s+", " ", command.strip())
        if cmd.startswith("no "):
            target = cmd[3:]
            # removing a whole block ("no interface Vlan5", "no banner login")
            before = len(self.entries)
            self.entries = [e for e in self.entries
                            if not ((e.children or e.text or e.block) and (e.line == target or e.line.startswith(target + " ")))]
            if len(self.entries) != before:
                return
        top = [e.line for e in self.entries if not (e.children or e.text or e.block) and e.line not in ("!", "end")]
        old = list(top)
        apply(top, cmd, self.platform)
        removed = [l for l in old if l not in top]
        added = [l for l in top if l not in old]
        self.entries = [e for e in self.entries if e.children or e.text or e.block or e.line not in removed]
        for line in added:
            self._insert(Entry(line))
