#pragma once

// Walking a file system object's DACL for the ACEs that can grant access.
//
// Every trust check on a key file, a folder above one, or a --dek-file asks
// the same question of each ACE: "does this let someone untrusted in?" Only
// the answer differs (which rights count, who is trusted, what the error
// says), so the walk itself lives here once:
//
//   - an inherit-only ACE is skipped: it applies only to objects created
//     inside a folder, which are checked on their own;
//   - a deny ACE is skipped: it only ever takes access away;
//   - an allow ACE, plain or callback (conditional), is handed to the
//     caller. The two share their layout up to the SID (header, mask, SID),
//     and a callback ACE is judged as if its condition held, since it may;
//   - anything else - an object or compound allow ACE, which never belongs
//     on a file system object - stops the walk, as does an ACE that can't
//     be read: neither can be vouched for.
//
// Shared by HkdfGuard.dll (key_file.cpp) and hkdfguard.exe. Header-only and
// exception-free, as no_follow_open.h is, so each caller raises its own
// error type: the visitor throws to refuse an ACE, and the caller turns a
// result other than Complete into an error. [[nodiscard]] so that can't be
// forgotten - ignoring it would let an unreadable ACE pass unexamined.

#include <windows.h>

namespace hkdfguard {

    enum class DaclWalkResult {
        Complete,      // every ACE was visited or skipped
        UnreadableAce, // GetAce failed; GetLastError() still says why
        UnexpectedAce, // an ACE of a type this walk can't judge
    };

    // Calls visit(PSID sid, ACCESS_MASK mask, BYTE aceFlags) for each
    // applicable allow ACE of `dacl`, which must not be null. `visit` is
    // taken by value, as the standard algorithms take callables: it is called
    // once per ACE, so it must not be forwarded (moved from).
    template <typename Visit>
    [[nodiscard]] DaclWalkResult WalkAllowAces(PACL dacl, Visit visit) {
        for (DWORD i = 0; i < dacl->AceCount; ++i) {
            void *ace = nullptr;
            if (!GetAce(dacl, i, &ace)) {
                return DaclWalkResult::UnreadableAce;
            }
            const auto *header = static_cast<const ACE_HEADER *>(ace);
            if (header->AceFlags & INHERIT_ONLY_ACE) {
                continue;
            }
            switch (header->AceType) {
                case ACCESS_DENIED_ACE_TYPE:
                case ACCESS_DENIED_OBJECT_ACE_TYPE:
                case ACCESS_DENIED_CALLBACK_ACE_TYPE:
                case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                    continue;
                case ACCESS_ALLOWED_ACE_TYPE:
                case ACCESS_ALLOWED_CALLBACK_ACE_TYPE: {
                    const auto *allowed = static_cast<const ACCESS_ALLOWED_ACE *>(ace);
                    visit(const_cast<DWORD *>(&allowed->SidStart), allowed->Mask, header->AceFlags);
                    continue;
                }
                default:
                    return DaclWalkResult::UnexpectedAce;
            }
        }
        return DaclWalkResult::Complete;
    }

} // namespace hkdfguard
