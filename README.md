# Permission Slip

> Tell one AI what it is allowed to do. Every AI knows.

Permission Slip is the human-facing portable authority and working-doctrine
layer. It is not the authority engine.

- **Permission Slip** is human-facing doctrine and authority UX. It normalises
  trusted agent actions, explains consequences, and coordinates admission.
- **Tethers** is the deterministic consequential authority engine. It is the
  single semantic authority that returns `ALLOW` / `ASK` / `DENY`.
- Permission Slip does **not** execute policy independently. It never decides
  that an action is authorised when Tethers has not authorised it.
- **AWS is optional future enforcement**, not required for local operation.

This repository currently contains a **v0.1 vertical integration spike** that
proves routine work flows almost silently while genuinely consequential
actions are intercepted, explained, and mechanically blocked until authorised.

Origin principle:

> The rant was the requirements interview.

See `feature/v0.1-vertical-spike` for the spike implementation.
