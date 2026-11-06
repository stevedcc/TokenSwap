/*
 * tswap's PC/SC loader (Linux NativeAOT builds only; TswapCli.csproj compiles it into libtswap_pcsc.a).
 *
 * Yubico.NativeShims 1.18.1's static archive calls 11 PC/SC functions, and its build targets would link
 * -lpcsclite, giving the binary a NEEDED entry for libpcsclite.so.1: without pcsc-lite installed it would not
 * start. tswap removes that -lpcsclite and defines the 11 functions here instead (design
 * docs/superpowers/specs/2026-11-04-yubikey-sdk-portable-design.md, "Constraints"). At the first call, once
 * (pthread_once), it picks a strategy for all 11 together:
 *   1 (system library): dlopen("libpcsclite.so.1") and dlsym of all 11 succeeded; every call is forwarded.
 *   2 (stand-in): the library or any one of the 11 symbols is missing; every call returns SCARD_E_NO_SERVICE
 *     and writes nothing through any output pointer. The SDK treats that like a machine without a smart-card
 *     service: no smart-card devices; keyboard (OTP) and FIDO HID devices are still found.
 * Never a mix. tswap_pcsc_strategy() reports it (0: not chosen yet), for `tswap -v yubikey setup`.
 *
 * Everything is compiled with -fvisibility=hidden: the 11 bind to Yubico.NativeShims' references at static
 * link and are never exported, so they can't interpose on a libpcsclite loaded by anything else.
 *
 * The types and prototypes below are copied from pcsc-lite 2.0.3 (src/PCSC/wintypes.h, src/PCSC/pcsclite.h.in,
 * src/PCSC/winscard.h; the non-Apple branch of wintypes.h): the pcsc-lite of Ubuntu 24.04's libpcsclite-dev,
 * whose <winscard.h> Yubico.NativeShims 1.18.1's pcsc.c includes in its Linux build. pcsc-lite 2.4.1 has the
 * same declarations. Their copyright and permission notice:
 *
 *   MUSCLE SmartCard Development ( https://pcsclite.apdu.fr/ )
 *
 *   Copyright (C) 1999-2004
 *    David Corcoran <corcoran@musclecard.com>
 *   Copyright (C) 2002-2011
 *    Ludovic Rousseau <ludovic.rousseau@free.fr>
 *   Copyright (C) 2005
 *    Martin Paljak <martin@paljak.pri.ee>
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *   3. The name of the author may not be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 *   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *   IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *   THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <dlfcn.h>
#include <pthread.h>
#include <stddef.h>

/* ---- pcsc-lite 2.0.3 declarations (see the notice above) ---- */

/* wintypes.h (non-Apple) */
typedef unsigned char BYTE;
typedef const void *LPCVOID;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef const BYTE *LPCBYTE;
typedef BYTE *LPBYTE;
typedef DWORD *LPDWORD;
typedef char *LPSTR;

/* pcsclite.h.in */
typedef LONG SCARDCONTEXT;
typedef SCARDCONTEXT *LPSCARDCONTEXT;
typedef LONG SCARDHANDLE;
typedef SCARDHANDLE *LPSCARDHANDLE;

#define MAX_ATR_SIZE 33

typedef struct
{
    const char *szReader;
    void *pvUserData;
    DWORD dwCurrentState;
    DWORD dwEventState;
    DWORD cbAtr;
    unsigned char rgbAtr[MAX_ATR_SIZE];
}
SCARD_READERSTATE;

typedef struct
{
    unsigned long dwProtocol;
    unsigned long cbPciLength;
}
SCARD_IO_REQUEST;

#define SCARD_E_NO_SERVICE ((LONG)0x8010001D)

/* ---- end of the pcsc-lite declarations ---- */

/*
 * The layout Yubico.NativeShims 1.18.1's archive was compiled with (its Native_SCardGetStatusChange allocates
 * 0x50 bytes per reader state and writes dwCurrentState/dwEventState/cbAtr/rgbAtr at 0x10/0x18/0x20/0x28).
 * tswap ships linux-x64 and linux-arm64, both LP64.
 */
_Static_assert(sizeof(long) == 8, "pcsc-loader.c assumes an LP64 target (linux-x64, linux-arm64)");
_Static_assert(sizeof(SCARD_READERSTATE) == 0x50, "SCARD_READERSTATE size");
_Static_assert(offsetof(SCARD_READERSTATE, dwCurrentState) == 0x10, "dwCurrentState offset");
_Static_assert(offsetof(SCARD_READERSTATE, dwEventState) == 0x18, "dwEventState offset");
_Static_assert(offsetof(SCARD_READERSTATE, cbAtr) == 0x20, "cbAtr offset");
_Static_assert(offsetof(SCARD_READERSTATE, rgbAtr) == 0x28, "rgbAtr offset");
_Static_assert(sizeof(SCARD_IO_REQUEST) == 16, "SCARD_IO_REQUEST size");

/*
 * The 11 functions, as X(name, parameters, arguments), prototypes as in pcsc-lite's winscard.h.
 */
#define TSWAP_PCSC_FUNCTIONS(X)                                                                                     \
    X(SCardEstablishContext,                                                                                        \
      (DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext),                          \
      (dwScope, pvReserved1, pvReserved2, phContext))                                                               \
    X(SCardReleaseContext, (SCARDCONTEXT hContext), (hContext))                                                     \
    X(SCardConnect,                                                                                                 \
      (SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, \
       LPDWORD pdwActiveProtocol),                                                                                  \
      (hContext, szReader, dwShareMode, dwPreferredProtocols, phCard, pdwActiveProtocol))                           \
    X(SCardReconnect,                                                                                               \
      (SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols, DWORD dwInitialization,                    \
       LPDWORD pdwActiveProtocol),                                                                                  \
      (hCard, dwShareMode, dwPreferredProtocols, dwInitialization, pdwActiveProtocol))                              \
    X(SCardDisconnect, (SCARDHANDLE hCard, DWORD dwDisposition), (hCard, dwDisposition))                            \
    X(SCardBeginTransaction, (SCARDHANDLE hCard), (hCard))                                                          \
    X(SCardEndTransaction, (SCARDHANDLE hCard, DWORD dwDisposition), (hCard, dwDisposition))                        \
    X(SCardGetStatusChange,                                                                                         \
      (SCARDCONTEXT hContext, DWORD dwTimeout, SCARD_READERSTATE *rgReaderStates, DWORD cReaders),                  \
      (hContext, dwTimeout, rgReaderStates, cReaders))                                                              \
    X(SCardTransmit,                                                                                                \
      (SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci, LPCBYTE pbSendBuffer, DWORD cbSendLength,             \
       SCARD_IO_REQUEST *pioRecvPci, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength),                                   \
      (hCard, pioSendPci, pbSendBuffer, cbSendLength, pioRecvPci, pbRecvBuffer, pcbRecvLength))                     \
    X(SCardListReaders,                                                                                             \
      (SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders),                             \
      (hContext, mszGroups, mszReaders, pcchReaders))                                                               \
    X(SCardCancel, (SCARDCONTEXT hContext), (hContext))

enum
{
    STRATEGY_NOT_CHOSEN = 0,
    STRATEGY_SYSTEM_LIBRARY = 1,
    STRATEGY_STAND_IN = 2,
};

#define TSWAP_PCSC_TYPEDEF(name, params, args) typedef LONG (*name##_fn) params;
TSWAP_PCSC_FUNCTIONS(TSWAP_PCSC_TYPEDEF)

static struct
{
#define TSWAP_PCSC_FIELD(name, params, args) name##_fn name;
    TSWAP_PCSC_FUNCTIONS(TSWAP_PCSC_FIELD)
} system_library;

static pthread_once_t choose_once = PTHREAD_ONCE_INIT;
static int strategy = STRATEGY_NOT_CHOSEN;

static void choose_strategy(void)
{
    int chosen = STRATEGY_STAND_IN;
    void *library = dlopen("libpcsclite.so.1", RTLD_NOW | RTLD_LOCAL);
    if (library != NULL)
    {
        int missing = 0;
        /* POSIX dlsym: a function pointer is stored through a void* lvalue (the form the dlsym page shows). */
#define TSWAP_PCSC_RESOLVE(name, params, args)                                                                      \
        *(void **)(&system_library.name) = dlsym(library, #name);                                                   \
        if (system_library.name == NULL)                                                                            \
            missing = 1;
        TSWAP_PCSC_FUNCTIONS(TSWAP_PCSC_RESOLVE)
        if (missing)
            dlclose(library); /* the stand-in answers all 11; the half-filled table is never read */
        else
            chosen = STRATEGY_SYSTEM_LIBRARY;
    }
    __atomic_store_n(&strategy, chosen, __ATOMIC_RELEASE);
}

static int current_strategy(void)
{
    pthread_once(&choose_once, choose_strategy);
    return __atomic_load_n(&strategy, __ATOMIC_ACQUIRE);
}

#define TSWAP_PCSC_DEFINE(name, params, args)                                                                       \
    LONG name params                                                                                                \
    {                                                                                                               \
        if (current_strategy() != STRATEGY_SYSTEM_LIBRARY)                                                          \
            return SCARD_E_NO_SERVICE;                                                                              \
        return system_library.name args;                                                                            \
    }
TSWAP_PCSC_FUNCTIONS(TSWAP_PCSC_DEFINE)

/* 0: no PC/SC call made yet, 1: system library, 2: stand-in. Read by TswapCli's PcscStrategy.Describe(). */
int tswap_pcsc_strategy(void)
{
    return __atomic_load_n(&strategy, __ATOMIC_ACQUIRE);
}
