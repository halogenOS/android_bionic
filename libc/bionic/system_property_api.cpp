/*
 * Copyright (C) 2017 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/system_properties.h>

#include <string.h>
#include <unistd.h>

#include <async_safe/CHECK.h>
#include <async_safe/log.h>
#include <system_properties/prop_area.h>
#include <system_properties/system_properties.h>

#include "private/bionic_defs.h"

static SystemProperties system_properties;
static_assert(__is_trivially_constructible(SystemProperties),
              "System Properties must be trivially constructable");

// Property interception for certified build spoofing.
// Values are stored in process-local memory only — not as system properties
// or files — to prevent detection by integrity checks.

namespace {

constexpr size_t kMaxSpoofEntries = 128;
constexpr size_t kNameCapacity = 128;

struct SpoofEntry {
  char name[kNameCapacity];
  char value[PROP_VALUE_MAX];
};

SpoofEntry g_spoof_entries[kMaxSpoofEntries];
volatile int g_spoof_count = 0;
volatile bool g_spoof_active = false;

static const char* const kHiddenPrefixes[] = {
    "persist.sys.pihooks.",
    "persist.sys.sussybox.",
};

bool is_hidden_prop(const char* name) {
  for (const auto& prefix : kHiddenPrefixes) {
    if (strncmp(name, prefix, strlen(prefix)) == 0) return true;
  }
  return false;
}

// Prefixes hidden only from processes that registered spoof entries (spoof
// targets). A stock device of the claimed identity has no such properties at
// all, so for those processes their mere existence contradicts the claimed
// identity even when their values are overridden. Hidden from every access
// path: by-name lookup, read, read-callback, and enumeration.
static const char* const kSpoofTargetHiddenPrefixes[] = {
    "ro.custom.",
    "init.svc.custom.",
};

bool is_spoof_target_hidden_prop(const char* name) {
  if (g_spoof_count == 0) return false;  // only processes with spoof entries
  for (const auto& prefix : kSpoofTargetHiddenPrefixes) {
    if (strncmp(name, prefix, strlen(prefix)) == 0) return true;
  }
  return false;
}

const char* get_spoofed_value(const char* name) {
  if (!g_spoof_active) return nullptr;
  for (int i = 0; i < g_spoof_count; i++) {
    if (strcmp(name, g_spoof_entries[i].name) == 0) {
      async_safe_format_log(ANDROID_LOG_DEBUG, "SysPropSpoof",
                            "Intercepted read: %s -> %s", name, g_spoof_entries[i].value);
      return g_spoof_entries[i].value;
    }
  }
  return nullptr;
}

// Log all property reads from spoofed processes for diagnostics
void log_prop_read(const char* name, const char* value) {
  if (g_spoof_count > 0 && name) {
    async_safe_format_log(ANDROID_LOG_DEBUG, "SysPropRead",
                          "%s = %s", name, value ? value : "(null)");
  }
}

}  // namespace

extern "C" void __system_property_spoof_add(const char* name, const char* value) {
  if (g_spoof_active) return;  // locked after enable
  if (g_spoof_count >= static_cast<int>(kMaxSpoofEntries)) return;
  const int idx = g_spoof_count;
  strlcpy(g_spoof_entries[idx].name, name, kNameCapacity);
  strlcpy(g_spoof_entries[idx].value, value, PROP_VALUE_MAX);
  g_spoof_count++;
  async_safe_format_log(ANDROID_LOG_INFO, "SysPropSpoof",
                        "Added spoof [%d]: %s = %s", idx, name, value);
}

extern "C" void __system_property_spoof_enable() {
  g_spoof_active = true;
  async_safe_format_log(ANDROID_LOG_INFO, "SysPropSpoof",
                        "Spoof enabled with %d entries", g_spoof_count);
}

// This is public because it was exposed in the NDK. As of 2017-01, ~60 apps reference this symbol.
// It is set to nullptr and never modified.
__BIONIC_WEAK_VARIABLE_FOR_NATIVE_BRIDGE
prop_area* __system_property_area__ = nullptr;

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_properties_init() {
  return system_properties.Init(PROP_DIRNAME) ? 0 : -1;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_set_filename(const char*) {
  return -1;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_area_init() {
  bool fsetxattr_fail = false;
  return system_properties.AreaInit(PROP_DIRNAME, &fsetxattr_fail) && !fsetxattr_fail ? 0 : -1;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
uint32_t __system_property_area_serial() {
  return system_properties.AreaSerial();
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
const prop_info* __system_property_find(const char* name) {
  if (__predict_false(is_hidden_prop(name) || is_spoof_target_hidden_prop(name))) {
    return nullptr;
  }
  return system_properties.Find(name);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_read(const prop_info* pi, char* name, char* value) {
  int len = system_properties.Read(pi, name, value);
  if (__predict_false(len > 0 && name)) {
    if (is_hidden_prop(name) || is_spoof_target_hidden_prop(name)) {
      value[0] = '\0';
      return 0;
    }
    const char* spoofed = get_spoofed_value(name);
    if (spoofed) return static_cast<int>(strlcpy(value, spoofed, PROP_VALUE_MAX));
  }
  return len;
}

namespace {

struct ReadCallbackWrapper {
  void (*original)(void*, const char*, const char*, uint32_t);
  void* cookie;
};

void intercepted_read_callback(void* wrapper_ptr, const char* name, const char* value,
                               uint32_t serial) {
  auto& w = *static_cast<ReadCallbackWrapper*>(wrapper_ptr);
  if (name) {
    if (is_hidden_prop(name) || is_spoof_target_hidden_prop(name)) {
      w.original(w.cookie, name, "", serial);
      return;
    }
    const char* spoofed = get_spoofed_value(name);
    if (spoofed) {
      w.original(w.cookie, name, spoofed, serial);
      return;
    }
    log_prop_read(name, value);
  }
  w.original(w.cookie, name, value, serial);
}

}  // namespace

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void __system_property_read_callback(const prop_info* pi,
                                     void (*callback)(void* cookie, const char* name,
                                                      const char* value, uint32_t serial),
                                     void* cookie) {
  ReadCallbackWrapper wrapper{callback, cookie};
  system_properties.ReadCallback(pi, intercepted_read_callback, &wrapper);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_get(const char* name, char* value) {
  if (__predict_false(is_hidden_prop(name) || is_spoof_target_hidden_prop(name))) {
    value[0] = '\0';
    return 0;
  }
  const char* spoofed = get_spoofed_value(name);
  if (spoofed) return static_cast<int>(strlcpy(value, spoofed, PROP_VALUE_MAX));
  int len = system_properties.Get(name, value);
  log_prop_read(name, value);
  return len;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_update(prop_info* pi, const char* value, unsigned int len) {
  return system_properties.Update(pi, value, len);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_add(const char* name, unsigned int namelen, const char* value,
                          unsigned int valuelen) {
  return system_properties.Add(name, namelen, value, valuelen);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
uint32_t __system_property_serial(const prop_info* pi) {
  // N.B. a previous version of this function was much heavier-weight
  // and enforced acquire semantics, so give our load here acquire
  // semantics just in case somebody depends on
  // __system_property_serial enforcing memory order, e.g., in case
  // someone spins on the result of this function changing before
  // loading some value.
  return atomic_load_explicit(&pi->serial, memory_order_acquire);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
uint32_t __system_property_wait_any(uint32_t old_serial) {
  return system_properties.WaitAny(old_serial);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
bool __system_property_wait(const prop_info* pi, uint32_t old_serial, uint32_t* new_serial_ptr,
                            const timespec* relative_timeout) {
  return system_properties.Wait(pi, old_serial, new_serial_ptr, relative_timeout);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
const prop_info* __system_property_find_nth(unsigned n) {
  return system_properties.FindNth(n);
}

namespace {

struct ForeachWrapper {
  void (*original)(const prop_info*, void*);
  void* cookie;
};

void filtered_foreach(const prop_info* pi, void* wrapper_ptr) {
  auto& w = *static_cast<ForeachWrapper*>(wrapper_ptr);
  char name[kNameCapacity];
  char value[PROP_VALUE_MAX];
  memset(name, 0, sizeof(name));
  memset(value, 0, sizeof(value));
  if (system_properties.Read(pi, name, value) > 0 &&
      (is_hidden_prop(name) || is_spoof_target_hidden_prop(name))) {
    return;
  }
  w.original(pi, w.cookie);
}

}  // namespace

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_foreach(void (*propfn)(const prop_info* pi, void* cookie), void* cookie) {
  ForeachWrapper wrapper{propfn, cookie};
  return system_properties.Foreach(filtered_foreach, &wrapper);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_properties_zygote_reload(void) {
  CHECK(getpid() == gettid());
  return system_properties.Reload(false) ? 0 : -1;
}
