# Second evasion technique : Bypassing ETW

ETW stands for Event Tracing for Windows.
It is a framework that allows to trace events in the Windows kernel.
It is used by many tools like Sysinternals Process Monitor, Sysmon, etc.
It is also used by Windows Defender to detect malicious activity.

With this technique, we overwrite the function EtwEventWrite() in the ntdll.dll library, to make it instantly return, so that not any event is written in the ETW.