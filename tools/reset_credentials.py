"""Read and clear the saved credentials from outside the application.

WHY THIS EXISTS
v4.35 put one session gate in front of every route, and signing in means one
login against the Management Server. That leaves a door that can lock with the
key inside it:

    the saved Management Server address is wrong
      -> every sign-in fails, because it is tried against that address
      -> nobody can reach the Settings page, because it is behind the gate
      -> the address can only be corrected on the Settings page

It is not hypothetical. It happened on 2026-09-11, with a stored address of
`https://x.invalid` written by a stray test, and there was no way back through
the browser at all.

A saved record overrides .env, so editing .env does not help either - which is
the part that makes it a trap rather than an inconvenience.

This prints what the application would use and where each value comes from,
and can remove a saved record so that .env applies again. It never prints a
password and never asks for one.

    python -m tools.reset_credentials
    python -m tools.reset_credentials --clear checkpoint
    python -m tools.reset_credentials --clear all --yes

WHAT IT DOES NOT FIX
If the address is right and the Management Server is simply unreachable, a new
sign-in still cannot succeed - there is nothing to check the credentials
against. An existing session keeps working throughout, because the cookie is
verified locally and never touches the server.
"""

from __future__ import annotations

import argparse
import sys

from app import credential_store
from app.config import settings

TYPES = ("checkpoint", "gaia")


def _mask(value: str | None) -> str:
    return f"set ({len(value)} characters)" if value else "not set"


def show() -> None:
    stored = credential_store.load_all()
    print(f"credential store : {credential_store.ENC_FILE}")
    print(f"                   {'present' if credential_store.ENC_FILE.exists() else 'absent'}"
          f"   entries: {', '.join(stored) or 'none'}")
    print()

    cp = stored.get("checkpoint") or {}
    print("Check Point Management API")
    print(f"  address        {settings.checkpoint_mgmt!r}")
    print(f"                 from {'the saved record' if cp.get('mgmt') else '.env'}"
          f"{'  <- overrides .env' if cp.get('mgmt') else ''}")
    print(f"  username       {settings.checkpoint_user!r}"
          f"   from {'the saved record' if cp.get('user') else '.env'}")
    print(f"  password       {_mask(settings.checkpoint_password)}"
          f"   from {'the saved record' if cp.get('password') else '.env'}")
    print()

    g = stored.get("gaia") or {}
    print("Gaia API")
    print(f"  enabled        {settings.gaia_enabled}")
    print(f"  hosts          {settings.gaia_hosts or '(none)'}"
          f"   from {'the saved record' if g.get('hosts') else '.env'}")
    print(f"  password       {_mask(settings.gaia_password)}")
    print()

    # The whole point of the tool, said plainly.
    from app import auth
    if auth.configured():
        print("Sign-in is required, and will be attempted against")
        print(f"    {settings.checkpoint_mgmt}")
        print("If that address is wrong, clear the saved record below so that")
        print(".env applies again - the Settings page cannot be reached until")
        print("somebody has signed in.")
    else:
        print("Sign-in is NOT required: no Management address and username are")
        print("configured, so there is nobody to check a sign-in against and")
        print("the application is open to anyone who can reach the port.")


def clear(which: str, assume_yes: bool) -> int:
    targets = list(TYPES) if which == "all" else [which]
    stored = credential_store.load_all()
    present = [t for t in targets if t in stored]
    if not present:
        print(f"Nothing saved for {which}; .env already applies.")
        return 0

    print("About to remove the saved record for: " + ", ".join(present))
    print("The values in .env will apply again after the application restarts.")
    print("Nothing else is touched, and this cannot be undone.")
    if not assume_yes:
        if input("Type 'yes' to continue: ").strip().lower() != "yes":
            print("Cancelled; nothing was changed.")
            return 1

    for t in present:
        credential_store.delete(t)
        print(f"  removed {t}")
    print()
    print("Restart the application, then sign in. Re-enter the credentials on")
    print("the Settings page afterwards if you want them saved again.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m tools.reset_credentials",
        description="Show, and optionally clear, the saved credentials.")
    ap.add_argument("--clear", choices=(*TYPES, "all"),
                    help="remove a saved record so that .env applies again")
    ap.add_argument("--yes", action="store_true",
                    help="do not ask for confirmation")
    args = ap.parse_args(argv)

    if args.clear:
        return clear(args.clear, args.yes)
    show()
    return 0


if __name__ == "__main__":
    sys.exit(main())
