# Event-Horizon-SubAuth
This is a sub-authentication module for Windows NT 5.x.p up to NT 10.0
Its purpose is to validate time-stampted token for a given user upon a logon event.
If the current UTC timestamp is earlier than the timestamp from token - user is permitted to login,
otherwise - logon is denid with the error: STATUS_INVALID_LOGON_HOURS
