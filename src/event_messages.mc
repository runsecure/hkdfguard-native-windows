; // Message table for the "hkdfguard-native-windows" Application event log
; // source. Compiled by mc.exe into a resource linked into
; // HkdfGuardV1.dll (see CMakeLists.txt); the MSI registers
; // that DLL as the source's EventMessageFile so Event Viewer can render
; // these. Every message is just "%1": event_log.cpp builds the full text,
; // and the event *type* passed to ReportEventW sets the level.
; //
; // The IDs here must match the constants in event_log.cpp.
; //   1000-1999  informational / warning: KEK lifecycle
; //   2000-2999  failures

MessageIdTypedef=DWORD
LanguageNames=(English=0x409:MSG00409)

MessageId=1000
SymbolicName=HKDFGUARD_EVT_KEK_CREATED
Language=English
%1
.

MessageId=1001
SymbolicName=HKDFGUARD_EVT_KEK_CREATED_SOFTWARE_FALLBACK
Language=English
%1
.

MessageId=1002
SymbolicName=HKDFGUARD_EVT_DEK_WRAPPED
Language=English
%1
.

MessageId=1003
SymbolicName=HKDFGUARD_EVT_DEK_UNWRAPPED
Language=English
%1
.

MessageId=2000
SymbolicName=HKDFGUARD_EVT_ACCESS_DENIED
Language=English
%1
.

MessageId=2002
SymbolicName=HKDFGUARD_EVT_KEK_ACL_INVALID
Language=English
%1
.

MessageId=2003
SymbolicName=HKDFGUARD_EVT_INTEGRITY_FAILURE
Language=English
%1
.

MessageId=2004
SymbolicName=HKDFGUARD_EVT_POLICY_INVALID
Language=English
%1
.

MessageId=2005
SymbolicName=HKDFGUARD_EVT_OPERATION_FAILED
Language=English
%1
.
