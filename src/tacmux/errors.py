"""Domain exceptions presented to operators without tracebacks."""


class TacmuxError(Exception):
    """Base class for expected TACMUX failures."""


class ValidationError(TacmuxError):
    """Persistent or operator-supplied data is invalid."""


class ConflictError(TacmuxError):
    """The requested operation conflicts with existing state."""


class ExternalToolError(TacmuxError):
    """tmux, Nmap, NOCAP, or an editor failed."""


class SafetyError(TacmuxError):
    """A containment or destructive-operation guard rejected an action."""
