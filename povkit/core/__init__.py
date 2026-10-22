"""The safety core every product module goes through: naming, ledger, change list, guards, checks, secrets."""


class KitError(Exception):
    """A failure the SE can act on; the message says what to do."""


class GuardError(KitError):
    """The kit refused a call that would break the customer-tenant safety rules. Nothing was sent."""
