"""
Unattended review runs.

Everything under here exists to answer one question the application could not
answer before: *what did the policy look like this morning, and what changed
since yesterday* - without somebody sitting at the browser clicking through
five pages and waiting out a 47-second analysis.

The design constraint that shapes all of it: **the runner must not know how it
was triggered.** `runner.run_review()` takes a Management API client and a
package and does the work. Three different things call it:

    a button in the UI          -> app/api/jobs.py
    a schedule inside the app   -> app/jobs/schedule.py   (Phase B)
    Windows Task Scheduler,
    cron, or a Docker sidecar   -> tools/run_review.py

That is deliberate, and it is the answer to "I am not sure yet where this will
run - build it so it can be moved". Moving the trigger out of the application
later means pointing Task Scheduler at the CLI and turning the in-app schedule
off. No part of the runner changes.

Nothing here adds a new kind of read. A review run calls the same `show-*`
service functions the pages already call, in the same order, through the same
paced client - so it inherits the rate limiting, the `heavy_lock`, the cache
and the tri-state honesty of everything it composes.
"""
