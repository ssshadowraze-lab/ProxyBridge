// ProxyBridge CLI for Windows
// Loads a .pbprofile exported from the GUI and runs it headless.
// Requires: ProxyBridgeCore.dll + WinDivert in same directory, Administrator rights.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")


#define VERSION "4.0.13-Beta"
#define MAX_PROXY_CONFIGS 256
#define MAX_RULES         512


typedef uint32_t (*pfnAddProxyConfig)(int type, const char* ip, uint16_t port,
                                      const char* user, const char* pass,
                                      int send_domain_to_proxy);
typedef uint32_t (*pfnAddRule)(const char* process, const char* hosts,
                               const char* ports, const char* domains,
                               int protocol, int action,
                               uint32_t config_id);
typedef int  (*pfnDisableRule)(uint32_t rule_id);
typedef int  (*pfnEnableRule)(uint32_t rule_id);
typedef int  (*pfnEditProxyConfig)(uint32_t id, int type, const char* ip, uint16_t port,
                                   const char* user, const char* pass, int send_domain);
typedef int  (*pfnDeleteProxyConfig)(uint32_t id);
typedef int  (*pfnEditRule)(uint32_t rule_id, const char* process, const char* hosts,
                            const char* ports, const char* domains,
                            int protocol, int action, uint32_t config_id);
typedef int  (*pfnDeleteRule)(uint32_t rule_id);
typedef void (*pfnSetLogCallback)(void (*cb)(const char*));
typedef void (*pfnSetConnectionCallback)(void (*cb)(const char*, DWORD,
                                          const char*, uint16_t, const char*));
typedef void (*pfnSetLocalhostViaProxy)(int enable);
typedef void (*pfnSetTrafficLogging)(int enable);
typedef int  (*pfnStart)(void);
typedef int  (*pfnStop)(void);

static pfnAddProxyConfig        g_AddProxyConfig = NULL;
static pfnAddRule               g_AddRule        = NULL;
static pfnDisableRule           g_DisableRule    = NULL;
static pfnEnableRule            g_EnableRule     = NULL;
static pfnEditProxyConfig       g_EditProxyConfig = NULL;
static pfnDeleteProxyConfig     g_DeleteProxyConfig = NULL;
static pfnEditRule              g_EditRule       = NULL;
static pfnDeleteRule            g_DeleteRule     = NULL;
static pfnSetLogCallback        g_SetLog         = NULL;
static pfnSetConnectionCallback g_SetConn        = NULL;
static pfnSetLocalhostViaProxy  g_SetLocalhost   = NULL;
static pfnSetTrafficLogging     g_SetTraffic     = NULL;
static pfnStart                 g_Start          = NULL;
static pfnStop                  g_Stop           = NULL;
static HMODULE                  g_hDll           = NULL;

// Profile structures
typedef struct {
    uint32_t profile_id;     // "Id" from JSON
    int      type;           // 0=HTTP, 1=SOCKS5
    char     host[256];
    int      port;
    char     username[256];
    char     password[256];
    int      send_domain_to_proxy;   // 1 = proxy resolves DNS (default), 0 = send IP
} PBProxyConfig;

typedef struct {
    char     process_name[256];
    char     target_hosts[512];
    char     target_ports[256];
    char     target_domains[512];  // "*", "google.com", "*.google.com;*.gstatic.com"
    int      protocol;        // 0=TCP, 1=UDP, 2=BOTH
    int      action;          // 0=PROXY, 1=DIRECT, 2=BLOCK
    int      is_enabled;
    uint32_t proxy_config_id; // maps to PBProxyConfig.profile_id
} PBRule;

typedef struct {
    int         localhost_via_proxy;
    int         traffic_logging;
    PBProxyConfig configs[MAX_PROXY_CONFIGS];
    int         num_configs;
    PBRule      rules[MAX_RULES];
    int         num_rules;
} PBProfile;

// Globals
static volatile LONG g_running = 0;
static int           g_verbose = 0;

// ── Hot-reload state ──────────────────────────────────────────────────────────
// Snapshot of what is currently live in the engine, so that when the profile file
// changes we can diff it and apply ONLY the delta - add new workers, edit changed
// proxies/rules (e.g. a rotated password) and delete removed ones - all without
// restarting the bridge and tearing down everyone else's live connections.
// Configs are keyed by the profile's "Id"; rules by their ProcessName (e.g.
// "@worker011"), which is this deployment's one-rule-per-worker identity.
typedef struct {
    uint32_t profile_id;          // "Id" from the profile
    uint32_t dll_id;              // id the engine assigned
    PBProxyConfig snap;           // last-applied content (to detect edits)
    int      seen;                // marked while diffing a reload
} AppliedConfig;

typedef struct {
    uint32_t dll_id;              // rule id the engine assigned
    PBRule   snap;                // last-applied content (process_name is the key)
    int      seen;
} AppliedRule;

static AppliedConfig g_cfg[MAX_PROXY_CONFIGS];
static int           g_cfg_n = 0;
static AppliedRule   g_rule[MAX_RULES];
static int           g_rule_n = 0;

// Callbacks
static void log_cb(const char* msg)
{
    if (g_verbose == 1 || g_verbose == 3)
        printf("[LOG]  %s\n", msg);
}

static void conn_cb(const char* process, DWORD pid,
                    const char* ip, uint16_t port, const char* proxy_info)
{
    if (g_verbose == 2 || g_verbose == 3)
        printf("[CONN] %s (PID:%lu) -> %s:%u via %s\n",
               process, (unsigned long)pid, ip, (unsigned)port, proxy_info);
}

// Banner
static void show_banner(void)
{
    printf("\n");
    printf("  ____                        ____       _     _            \n");
    printf(" |  _ \\ _ __ _____  ___   _  | __ ) _ __(_) __| | __ _  ___ \n");
    printf(" | |_) | '__/ _ \\ \\/ / | | | |  _ \\| '__| |/ _` |/ _` |/ _ \\\n");
    printf(" |  __/| | | (_) >  <| |_| | | |_) | |  | | (_| | (_| |  __/\n");
    printf(" |_|   |_|  \\___/_/\\_\\\\__, | |____/|_|  |_|\\__,_|\\__, |\\___|\n");
    printf("                      |___/                      |___/  V%s\n", VERSION);
    printf("\n");
    printf("  Universal proxy client for Windows applications\n");
    printf("\n");
    printf("\tAuthor: Sourav Kalal/InterceptSuite\n");
    printf("\tGitHub: https://github.com/InterceptSuite/ProxyBridge\n");
    printf("\n");
}

static void show_help(const char* prog)
{
    show_banner();
    printf("Description:\n");
    printf("  ProxyBridge CLI - Run a ProxyBridge profile headlessly.\n\n");
    printf("Usage:\n");
    printf("  %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  --profile <path>     Path to .pbprofile file\n");
    printf("                       Export from the GUI: File > Export Profile\n\n");
    printf("  --verbose <0-3>      Logging verbosity\n");
    printf("                         0 - Silent (default)\n");
    printf("                         1 - Log messages only\n");
    printf("                         2 - Connection events only\n");
    printf("                         3 - Both logs and connections\n\n");
    printf("  --version            Show version information\n");
    printf("  -?, -h, --help       Show this help\n\n");
    printf("Commands:\n");
    printf("  --update             Check for updates and open releases page\n\n");
    printf("Examples:\n");
    printf("  ProxyBridge_CLI.exe --profile C:\\Users\\user\\myconfig.pbprofile\n");
    printf("  ProxyBridge_CLI.exe --profile myconfig.pbprofile --verbose 2\n");
    printf("  ProxyBridge_CLI.exe --update\n\n");
}

// Admin check . Windivert require admin
static bool is_admin(void)
{
    BOOL elevated = FALSE;
    HANDLE token  = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        TOKEN_ELEVATION elev;
        DWORD sz = sizeof(elev);
        if (GetTokenInformation(token, TokenElevation, &elev, sz, &sz))
            elevated = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}

// Minimal JSON helpers
// Returns pointer to the value portion of "key": <value> within json, or NULL.
static const char* jfind(const char* json, const char* key)
{
    char search[300];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

// Extract a JSON string value for key into out[size]. Returns true on success.
static bool jstr(const char* json, const char* key, char* out, size_t size)
{
    if (size == 0) return false;
    const char* p = jfind(json, key);
    if (!p || *p != '"') { out[0] = '\0'; return false; }
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < size - 1)
    {
        if (*p == '\\' && *(p + 1))
        {
            p++;
            switch (*p)
            {
                case '"':  out[i++] = '"';  break;
                case '\\': out[i++] = '\\'; break;
                case '/':  out[i++] = '/';  break;
                case 'n':  out[i++] = '\n'; break;
                case 'r':  out[i++] = '\r'; break;
                case 't':  out[i++] = '\t'; break;
                default:   out[i++] = *p;  break;
            }
        }
        else
            out[i++] = *p;
        p++;
    }
    out[i] = '\0';
    return true;
}

// Extract a JSON integer value for key.
static int jint(const char* json, const char* key, int def)
{
    const char* p = jfind(json, key);
    if (!p) return def;
    char* end = NULL;
    long v = strtol(p, &end, 10);
    return (end == p) ? def : (int)v;
}

// Extract a JSON boolean value for key.
static bool jbool(const char* json, const char* key, bool def)
{
    const char* p = jfind(json, key);
    if (!p) return def;
    if (strncmp(p, "true",  4) == 0) return true;
    if (strncmp(p, "false", 5) == 0) return false;
    return def;
}

// Returns pointer to first character after '[' of array "key", or NULL.
static const char* jarray(const char* json, const char* key)
{
    char search[300];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    while (*p && *p != '[' && *p != '}') p++;
    return (*p == '[') ? p + 1 : NULL;
}

// Advances to the next {...} object within an array.
// Returns pointer to '{', updates *next to char after matching '}'.
// Returns NULL when no more objects.
static const char* jnext_obj(const char* pos, const char** next)
{
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' ||
           *pos == '\r' || *pos == ',')
        pos++;

    if (*pos != '{') { *next = pos; return NULL; }

    // Cap object size to 4 MB to prevent huge malloc on malformed input
    const char* scan = pos;
    size_t remaining = strlen(scan);
    if (remaining > 4u * 1024u * 1024u) remaining = 4u * 1024u * 1024u;
    const char* limit = scan + remaining;

    const char* start  = pos;
    int         depth  = 0;
    bool        in_str = false;

    while (*pos && pos < limit)
    {
        if (in_str)
        {
            if (*pos == '\\') { pos++; if (*pos) pos++; continue; }
            if (*pos == '"')  in_str = false;
        }
        else
        {
            if      (*pos == '"') in_str = true;
            else if (*pos == '{') depth++;
            else if (*pos == '}') { if (--depth == 0) { *next = pos + 1; return start; } }
        }
        pos++;
    }
    *next = pos;
    return NULL;
}

// ── Profile loader ────────────────────────────────────────────────────────────
static char* read_file_text(const char* path, size_t* out_size)
{
    FILE* f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 4 * 1024 * 1024) { fclose(f); return NULL; }
    char* buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    *out_size = fread(buf, 1, (size_t)sz, f);
    buf[*out_size] = '\0';
    fclose(f);
    return buf;
}

static bool load_profile(const char* path, PBProfile* prof)
{
    size_t sz   = 0;
    char*  json = read_file_text(path, &sz);
    if (!json)
    {
        fprintf(stderr, "ERROR: Cannot read profile: %s\n", path);
        return false;
    }

    char ver[32] = {0};
    jstr(json, "Version", ver, sizeof(ver));
    if (ver[0] != '\0' && strcmp(ver, "1.0") != 0)
        printf("WARNING: Profile version '%s' may differ from expected 1.0.\n", ver);

    memset(prof, 0, sizeof(PBProfile));
    prof->localhost_via_proxy = jbool(json, "LocalhostViaProxy",        false) ? 1 : 0;
    prof->traffic_logging     = jbool(json, "IsTrafficLoggingEnabled",  true)  ? 1 : 0;

    // ── ProxyConfigs ──────────────────────────────────────────────────────────
    const char* arr = jarray(json, "ProxyConfigs");
    if (arr)
    {
        const char* next = arr;
        const char* obj;
        while ((obj = jnext_obj(next, &next)) != NULL &&
               prof->num_configs < MAX_PROXY_CONFIGS)
        {
            size_t len  = (size_t)(next - obj);
            char*  buf  = (char*)malloc(len + 1);
            if (!buf) break;
            memcpy(buf, obj, len);
            buf[len] = '\0';

            PBProxyConfig* c = &prof->configs[prof->num_configs];
            c->profile_id = (uint32_t)jint(buf, "Id", 0);

            char type_s[32] = {0};
            jstr(buf, "Type", type_s, sizeof(type_s));
            c->type = (_stricmp(type_s, "socks5") == 0) ? 1 : 0;

            jstr(buf, "Host", c->host, sizeof(c->host));

            // Port is serialized as a string in .pbprofile
            char port_s[16] = {0};
            jstr(buf, "Port", port_s, sizeof(port_s));
            char* port_end = NULL;
            long port_val = strtol(port_s, &port_end, 10);
            c->port = (port_end != port_s) ? (int)port_val : 0;

            jstr(buf, "Username", c->username, sizeof(c->username));
            jstr(buf, "Password", c->password, sizeof(c->password));

            // Boolean; default ON when the field is absent (older profiles).
            const char* sd = jfind(buf, "SendDomainToProxy");
            c->send_domain_to_proxy = (!sd || strncmp(sd, "true", 4) == 0) ? 1 : 0;

            free(buf);

            if (c->host[0] != '\0' && c->port > 0 && c->port <= 65535)
                prof->num_configs++;
        }
    }

    // ── ProxyRules ────────────────────────────────────────────────────────────
    arr = jarray(json, "ProxyRules");
    if (arr)
    {
        const char* next = arr;
        const char* obj;
        while ((obj = jnext_obj(next, &next)) != NULL &&
               prof->num_rules < MAX_RULES)
        {
            size_t len = (size_t)(next - obj);
            char*  buf = (char*)malloc(len + 1);
            if (!buf) break;
            memcpy(buf, obj, len);
            buf[len] = '\0';

            PBRule* r = &prof->rules[prof->num_rules];
            jstr(buf, "ProcessName", r->process_name, sizeof(r->process_name));
            jstr(buf, "TargetHosts", r->target_hosts,  sizeof(r->target_hosts));
            jstr(buf, "TargetPorts", r->target_ports,  sizeof(r->target_ports));
            jstr(buf, "TargetDomains", r->target_domains, sizeof(r->target_domains));

            char ps[16] = {0};
            jstr(buf, "Protocol", ps, sizeof(ps));
            if      (_stricmp(ps, "UDP")  == 0) r->protocol = 1;
            else if (_stricmp(ps, "BOTH") == 0) r->protocol = 2;
            else                                r->protocol = 0;

            char as[16] = {0};
            jstr(buf, "Action", as, sizeof(as));
            if      (_stricmp(as, "DIRECT") == 0) r->action = 1;
            else if (_stricmp(as, "BLOCK")  == 0) r->action = 2;
            else                                  r->action = 0;

            r->is_enabled      = jbool(buf, "IsEnabled", true) ? 1 : 0;
            r->proxy_config_id = (uint32_t)jint(buf, "ProxyConfigId", 0);

            free(buf);
            prof->num_rules++;
        }
    }

    free(json);
    return true;
}

// ── Sync a parsed profile into the running engine (add / edit / delete) ───────
// On the first call this loads the whole profile. On later calls (the profile
// file changed on disk) it diffs against what is already live and applies only
// the delta: new workers are added, changed proxies/rules are edited in place
// (e.g. a rotated SOCKS password), and removed ones are deleted - all without
// restarting the bridge, so everyone else's live connections are untouched.
// Returns the number of changes (adds + edits + deletes) applied.
static uint32_t resolve_dll_cfg_id(uint32_t profile_cfg_id)
{
    for (int j = 0; j < g_cfg_n; j++)
        if (g_cfg[j].profile_id == profile_cfg_id)
            return g_cfg[j].dll_id;
    return (g_cfg_n > 0) ? g_cfg[0].dll_id : 0;   // fallback: first config
}

static bool config_differs(const PBProxyConfig* a, const PBProxyConfig* b)
{
    return a->type != b->type || a->port != b->port ||
           a->send_domain_to_proxy != b->send_domain_to_proxy ||
           strcmp(a->host, b->host)         != 0 ||
           strcmp(a->username, b->username) != 0 ||
           strcmp(a->password, b->password) != 0;
}

static bool rule_differs(const PBRule* a, const PBRule* b)
{
    return a->protocol != b->protocol || a->action != b->action ||
           a->is_enabled != b->is_enabled || a->proxy_config_id != b->proxy_config_id ||
           strcmp(a->target_hosts,   b->target_hosts)   != 0 ||
           strcmp(a->target_ports,   b->target_ports)   != 0 ||
           strcmp(a->target_domains, b->target_domains) != 0;
}

static const char* action_name(int a)
{
    return a == 0 ? "PROXY" : (a == 1 ? "DIRECT" : "BLOCK");
}

static int sync_profile(const PBProfile* prof, bool initial)
{
    const char* tag = initial ? "[+]" : "[hot]";
    int changes = 0;

    for (int i = 0; i < g_cfg_n;  i++) g_cfg[i].seen  = 0;
    for (int i = 0; i < g_rule_n; i++) g_rule[i].seen = 0;

    // ── Proxy configs: add new, edit changed (keyed by profile "Id") ─────────
    for (int i = 0; i < prof->num_configs; i++)
    {
        const PBProxyConfig* c = &prof->configs[i];

        int idx = -1;
        for (int j = 0; j < g_cfg_n; j++)
            if (g_cfg[j].profile_id == c->profile_id) { idx = j; break; }

        if (idx < 0)   // new config
        {
            uint32_t did = g_AddProxyConfig(c->type, c->host, (uint16_t)c->port,
                                            c->username, c->password, c->send_domain_to_proxy);
            if (did == 0)
            {
                fprintf(stderr, "  ERROR: add proxy config id=%u (%s:%d) failed\n",
                        c->profile_id, c->host, c->port);
                continue;
            }
            if (g_cfg_n < MAX_PROXY_CONFIGS)
            {
                g_cfg[g_cfg_n].profile_id = c->profile_id;
                g_cfg[g_cfg_n].dll_id     = did;
                g_cfg[g_cfg_n].snap       = *c;
                g_cfg[g_cfg_n].seen       = 1;
                g_cfg_n++;
            }
            changes++;
            printf("  %s add  config id=%u  %s  %s:%d\n", tag,
                   c->profile_id, c->type ? "SOCKS5" : "HTTP", c->host, c->port);
        }
        else           // existing config - edit if changed
        {
            g_cfg[idx].seen = 1;
            if (config_differs(&g_cfg[idx].snap, c))
            {
                if (g_EditProxyConfig(g_cfg[idx].dll_id, c->type, c->host, (uint16_t)c->port,
                                      c->username, c->password, c->send_domain_to_proxy))
                {
                    g_cfg[idx].snap = *c;
                    changes++;
                    printf("  %s edit config id=%u  %s:%d\n", tag,
                           c->profile_id, c->host, c->port);
                }
                else
                    fprintf(stderr, "  WARNING: edit proxy config id=%u failed\n", c->profile_id);
            }
        }
    }

    // ── Rules: add new, edit changed (keyed by ProcessName) ──────────────────
    for (int i = 0; i < prof->num_rules; i++)
    {
        // Normalise so stored snapshot == what we actually push (defaults applied).
        PBRule nr = prof->rules[i];
        if (!nr.process_name[0])   strncpy_s(nr.process_name,   sizeof(nr.process_name),   "*", _TRUNCATE);
        if (!nr.target_hosts[0])   strncpy_s(nr.target_hosts,   sizeof(nr.target_hosts),   "*", _TRUNCATE);
        if (!nr.target_ports[0])   strncpy_s(nr.target_ports,   sizeof(nr.target_ports),   "*", _TRUNCATE);
        if (!nr.target_domains[0]) strncpy_s(nr.target_domains, sizeof(nr.target_domains), "*", _TRUNCATE);

        uint32_t dll_cfg_id = (nr.action == 0) ? resolve_dll_cfg_id(nr.proxy_config_id) : 0;

        int idx = -1;
        for (int j = 0; j < g_rule_n; j++)
            if (strcmp(g_rule[j].snap.process_name, nr.process_name) == 0) { idx = j; break; }

        if (idx < 0)   // new rule
        {
            uint32_t rid = g_AddRule(nr.process_name, nr.target_hosts, nr.target_ports,
                                     nr.target_domains, nr.protocol, nr.action, dll_cfg_id);
            if (rid == 0)
            {
                fprintf(stderr, "  WARNING: add rule (%s) failed\n", nr.process_name);
                continue;
            }
            if (!nr.is_enabled) g_DisableRule(rid);
            if (g_rule_n < MAX_RULES)
            {
                g_rule[g_rule_n].dll_id = rid;
                g_rule[g_rule_n].snap   = nr;
                g_rule[g_rule_n].seen   = 1;
                g_rule_n++;
            }
            changes++;
            printf("  %s add  rule %-26s cfg=%u  %s%s\n", tag,
                   nr.process_name, nr.proxy_config_id, action_name(nr.action),
                   nr.is_enabled ? "" : "  [disabled]");
        }
        else           // existing rule - edit if changed
        {
            g_rule[idx].seen = 1;
            if (rule_differs(&g_rule[idx].snap, &nr))
            {
                if (g_EditRule(g_rule[idx].dll_id, nr.process_name, nr.target_hosts,
                               nr.target_ports, nr.target_domains, nr.protocol,
                               nr.action, dll_cfg_id))
                {
                    if (nr.is_enabled != g_rule[idx].snap.is_enabled)
                    {
                        if (nr.is_enabled) g_EnableRule(g_rule[idx].dll_id);
                        else               g_DisableRule(g_rule[idx].dll_id);
                    }
                    g_rule[idx].snap = nr;
                    changes++;
                    printf("  %s edit rule %-26s cfg=%u  %s%s\n", tag,
                           nr.process_name, nr.proxy_config_id, action_name(nr.action),
                           nr.is_enabled ? "" : "  [disabled]");
                }
                else
                    fprintf(stderr, "  WARNING: edit rule (%s) failed\n", nr.process_name);
            }
        }
    }

    // ── Deletions: rules first (they reference configs), then configs ────────
    for (int j = g_rule_n - 1; j >= 0; j--)
    {
        if (g_rule[j].seen) continue;
        g_DeleteRule(g_rule[j].dll_id);
        printf("  %s del  rule %s\n", tag, g_rule[j].snap.process_name);
        changes++;
        g_rule[j] = g_rule[--g_rule_n];   // compact
    }
    for (int j = g_cfg_n - 1; j >= 0; j--)
    {
        if (g_cfg[j].seen) continue;
        g_DeleteProxyConfig(g_cfg[j].dll_id);
        printf("  %s del  config id=%u\n", tag, g_cfg[j].profile_id);
        changes++;
        g_cfg[j] = g_cfg[--g_cfg_n];      // compact
    }

    return changes;
}

// ── DLL loader ────────────────────────────────────────────────────────────────
#define LOAD_FN(type, var, name)                                                  \
    do {                                                                          \
        (var) = (type)GetProcAddress(g_hDll, (name));                            \
        if (!(var)) {                                                             \
            fprintf(stderr, "ERROR: '%s' not found in ProxyBridgeCore.dll\n",    \
                    (name));                                                      \
            return false;                                                         \
        }                                                                         \
    } while (0)

static bool load_dll(void)
{
    char dll_path[MAX_PATH];
    GetModuleFileNameA(NULL, dll_path, MAX_PATH);
    char* sep = strrchr(dll_path, '\\');
    if (sep)
    {
        size_t remaining = (size_t)(dll_path + MAX_PATH - (sep + 1));
        strncpy_s(sep + 1, remaining, "ProxyBridgeCore.dll", _TRUNCATE);
    }
    else
        strncpy_s(dll_path, MAX_PATH, "ProxyBridgeCore.dll", _TRUNCATE);

    // use only the resolved absolute path no bare-name fallback to prevent
    // DLL hijacking via current working directory.
    g_hDll = LoadLibraryExA(dll_path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!g_hDll)
    {
        fprintf(stderr, "ERROR: Cannot load ProxyBridgeCore.dll (error %lu)\n",
                GetLastError());
        fprintf(stderr, "Ensure ProxyBridgeCore.dll is in the same directory.\n");
        return false;
    }

    LOAD_FN(pfnAddProxyConfig,        g_AddProxyConfig, "ProxyBridge_AddProxyConfig");
    LOAD_FN(pfnAddRule,               g_AddRule,        "ProxyBridge_AddRule");
    LOAD_FN(pfnDisableRule,           g_DisableRule,    "ProxyBridge_DisableRule");
    LOAD_FN(pfnEnableRule,            g_EnableRule,     "ProxyBridge_EnableRule");
    LOAD_FN(pfnEditProxyConfig,       g_EditProxyConfig, "ProxyBridge_EditProxyConfig");
    LOAD_FN(pfnDeleteProxyConfig,     g_DeleteProxyConfig, "ProxyBridge_DeleteProxyConfig");
    LOAD_FN(pfnEditRule,              g_EditRule,       "ProxyBridge_EditRule");
    LOAD_FN(pfnDeleteRule,            g_DeleteRule,     "ProxyBridge_DeleteRule");
    LOAD_FN(pfnSetLogCallback,        g_SetLog,         "ProxyBridge_SetLogCallback");
    LOAD_FN(pfnSetConnectionCallback, g_SetConn,        "ProxyBridge_SetConnectionCallback");
    LOAD_FN(pfnSetLocalhostViaProxy,  g_SetLocalhost,   "ProxyBridge_SetLocalhostViaProxy");
    LOAD_FN(pfnSetTrafficLogging,     g_SetTraffic,     "ProxyBridge_SetTrafficLoggingEnabled");
    LOAD_FN(pfnStart,                 g_Start,          "ProxyBridge_Start");
    LOAD_FN(pfnStop,                  g_Stop,           "ProxyBridge_Stop");

    return true;
}

#undef LOAD_FN

// ── Ctrl+C / close handler ────────────────────────────────────────────────────
static BOOL WINAPI ctrl_handler(DWORD ev)
{
    if (ev == CTRL_C_EVENT || ev == CTRL_BREAK_EVENT || ev == CTRL_CLOSE_EVENT)
    {
        if (InterlockedExchange(&g_running, 0))
        {
            printf("\nStopping ProxyBridge...\n");
            if (g_Stop) g_Stop();
        }
        return TRUE;
    }
    return FALSE;
}

// ── Download a URL to a local file, following redirects ──────────────────────
// url must be https://hostname/path  (no query string needed for GitHub CDN)
// Returns true on success.
static bool download_file(const char* url, const char* dest_path)
{
    // Parse host and path from the URL
    // Expected format: https://hostname/path...
    const char* after_scheme = strstr(url, "://");
    if (!after_scheme) return false;
    after_scheme += 3;

    const char* path_start = strchr(after_scheme, '/');
    if (!path_start) return false;

    size_t host_len = (size_t)(path_start - after_scheme);
    if (host_len == 0 || host_len > 512) return false;

    wchar_t whost[512] = {0};
    if (MultiByteToWideChar(CP_UTF8, 0, after_scheme, (int)host_len, whost, 511) == 0)
        return false;

    wchar_t wpath[2048] = {0};
    if (MultiByteToWideChar(CP_UTF8, 0, path_start, -1, wpath, 2047) == 0)
        return false;

    HINTERNET sess = WinHttpOpen(L"ProxyBridge-CLI/1.0",
                                  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                  WINHTTP_NO_PROXY_NAME,
                                  WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) return false;

    HINTERNET conn = WinHttpConnect(sess, whost,
                                     INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) { WinHttpCloseHandle(sess); return false; }

    HINTERNET req = WinHttpOpenRequest(conn, L"GET", wpath,
                                        NULL, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!req)
    {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return false;
    }

    bool ok = false;
    if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(req, NULL))
    {
        // Check HTTP status
        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
            WINHTTP_NO_HEADER_INDEX);

        if (status == 200)
        {
            FILE* f = NULL;
            fopen_s(&f, dest_path, "wb");
            if (f)
            {
                DWORD avail = 0, rd = 0;
                char  buf[65536];
                ok = true;
                while (WinHttpQueryDataAvailable(req, &avail) && avail > 0)
                {
                    DWORD chunk = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
                    if (!WinHttpReadData(req, buf, chunk, &rd) || rd == 0)
                        { ok = false; break; }
                    if (fwrite(buf, 1, rd, f) != rd)
                        { ok = false; break; }
                }
                fclose(f);
                if (!ok) DeleteFileA(dest_path);
            }
        }
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(sess);
    return ok;
}

// ── Update check ──────────────────────────────────────────────────────────────
static int parse_ver(const char* s)
{
    if (!s || !*s) return 0;
    if (*s == 'v' || *s == 'V') s++;
    int a = 0, b = 0, c = 0;
    sscanf_s(s, "%d.%d.%d", &a, &b, &c);
    // Clamp to prevent overflow in a * 10000
    if (a < 0 || a > 9999) a = 0;
    if (b < 0 || b > 99)   b = 0;
    if (c < 0 || c > 99)   c = 0;
    return a * 10000 + b * 100 + c;
}

static void do_update(void)
{
    printf("Checking for updates...\n\n");

    HINTERNET sess = WinHttpOpen(L"ProxyBridge-CLI/1.0",
                                  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                  WINHTTP_NO_PROXY_NAME,
                                  WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) { printf("ERROR: WinHTTP init failed (%lu).\n", GetLastError()); return; }

    HINTERNET conn = WinHttpConnect(sess, L"api.github.com",
                                     INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) { WinHttpCloseHandle(sess); printf("ERROR: Connection failed.\n"); return; }

    HINTERNET req = WinHttpOpenRequest(conn, L"GET",
        L"/repos/InterceptSuite/ProxyBridge/releases/latest",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!req)
    {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        printf("ERROR: Request failed.\n");
        return;
    }

    WinHttpAddRequestHeaders(req,
        L"Accept: application/vnd.github.v3+json",
        (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    char*  response = NULL;
    DWORD  total    = 0;

    if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(req, NULL))
    {
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(req, &avail) && avail > 0)
        {
            // Guard against DWORD overflow and cap response at 256 KB
            if (avail > 256u * 1024u || total > 256u * 1024u - avail) break;
            char* tmp = (char*)realloc(response, total + avail + 1);
            if (!tmp) break;
            response = tmp;
            DWORD rd = 0;
            if (!WinHttpReadData(req, response + total, avail, &rd) || rd == 0) break;
            total += rd;
            response[total] = '\0';
        }
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(sess);

    if (!response)
    {
        printf("ERROR: No response received from GitHub.\n");
        return;
    }

    char tag[64] = {0};
    jstr(response, "tag_name", tag, sizeof(tag));

    // Check assets array for a Windows .exe installer
    // Same logic as GUI UpdateService: only announce update if Windows
    // installer asset is present in the release (Mac/Linux releases won't have one).
    char download_url[1024] = {0};
    char asset_name[256]    = {0};
    bool has_win_installer  = false;

    const char* assets = jarray(response, "assets");
    if (assets)
    {
        const char* next = assets;
        const char* obj;
        while ((obj = jnext_obj(next, &next)) != NULL)
        {
            size_t len = (size_t)(next - obj);
            char*  buf = (char*)malloc(len + 1);
            if (!buf) break;
            memcpy(buf, obj, len);
            buf[len] = '\0';

            char name[256] = {0};
            jstr(buf, "name", name, sizeof(name));

            // Must end in .exe
            size_t nlen = strlen(name);
            bool is_exe = nlen > 4 && _stricmp(name + nlen - 4, ".exe") == 0;

            if (is_exe && (
                    _stricmp(name, "") != 0) &&
                    (strstr(name, "setup")      != NULL ||
                     strstr(name, "Setup")      != NULL ||
                     strstr(name, "installer")  != NULL ||
                     strstr(name, "Installer")  != NULL ||
                     strstr(name, "ProxyBridge") != NULL))
            {
                jstr(buf, "browser_download_url", download_url, sizeof(download_url));
                // Extract only the filename portion to prevent path traversal
                // (e.g. asset names like "..\evil.exe" from a malicious response)
                const char* fname = name;
                const char* sl = strrchr(name, '/');
                const char* bs = strrchr(name, '\\');
                if (sl)  fname = sl  + 1;
                if (bs && bs > fname) fname = bs + 1;
                // Reject empty or dot-only names
                if (fname[0] == '\0' || strcmp(fname, ".") == 0 || strcmp(fname, "..") == 0)
                    { free(buf); continue; }
                strncpy_s(asset_name, sizeof(asset_name), fname, _TRUNCATE);
                has_win_installer = true;
                free(buf);
                break;
            }
            free(buf);
        }
    }

    free(response);

    if (!tag[0])
    {
        printf("ERROR: Could not parse release data from GitHub API.\n");
        return;
    }

    int latest  = parse_ver(tag);
    int current = parse_ver(VERSION);

    printf("  Current version : %s\n",  VERSION);
    printf("  Latest version  : %s\n\n", tag);

    if (latest <= current)
    {
        printf("You are already running the latest version.\n\n");
        return;
    }

    if (!has_win_installer)
    {
        printf("  A newer version (%s) exists but no Windows installer was\n", tag);
        printf("  found in that release yet. Check back later.\n\n");
        return;
    }

    printf("  Update available: %s\n\n", asset_name);
    printf("Download and install now? [Y/N]: ");
    fflush(stdout);
    int ch = getchar();
    if (ch != 'y' && ch != 'Y')
    {
        printf("\n");
        return;
    }

    // Build temp path: %TEMP%\<asset_name>
    char tmp_dir[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, tmp_dir);
    char dest[MAX_PATH] = {0};
    // Ensure tmp_dir + asset_name fits within MAX_PATH
    size_t tmp_len = strnlen_s(tmp_dir, MAX_PATH);
    size_t name_len = strnlen_s(asset_name, sizeof(asset_name));
    if (tmp_len + name_len + 1 > MAX_PATH)
    {
        fprintf(stderr, "ERROR: Temp path too long.\n");
        return;
    }
    snprintf(dest, MAX_PATH, "%s%s", tmp_dir, asset_name);

    printf("\nDownloading %s...\n", asset_name);
    fflush(stdout);

    if (!download_file(download_url, dest))
    {
        fprintf(stderr, "ERROR: Download failed.\n");
        fprintf(stderr, "Download manually: %s\n\n", download_url);
        return;
    }

    printf("Download complete: %s\n", dest);
    printf("Launching installer...\n\n");

    // Launch the installer and exit; installer handles the rest
    HINSTANCE result = ShellExecuteA(NULL, "runas", dest, NULL, NULL, SW_SHOWNORMAL);
    if ((INT_PTR)result <= 32)
    {
        fprintf(stderr, "ERROR: Could not launch installer (code %lld).\n",
                (long long)(INT_PTR)result);
        fprintf(stderr, "Run manually: %s\n\n", dest);
        return;
    }

    exit(0);
}

// ── main ──────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    bool do_upd       = false;
    char profile_path[MAX_PATH] = {0};

    // No args: show full help
    if (argc < 2)
    {
        show_help(argv[0]);
        return 0;
    }

    // Parse arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 ||
            strcmp(argv[i], "-h")     == 0 ||
            strcmp(argv[i], "-?")     == 0)
        {
            show_help(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--version") == 0)
        {
            show_banner();
            printf("Version: %s\n\n", VERSION);
            return 0;
        }
        else if (strcmp(argv[i], "--update") == 0)
        {
            do_upd = true;
        }
        else if (strcmp(argv[i], "--profile") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "ERROR: --profile requires a file path.\n");
                return 1;
            }
            strncpy_s(profile_path, MAX_PATH, argv[++i], _TRUNCATE);
        }
        else if (strcmp(argv[i], "--verbose") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "ERROR: --verbose requires a level (0-3).\n");
                return 1;
            }
            char* vend = NULL;
            g_verbose = (int)strtol(argv[++i], &vend, 10);
            if (*vend != '\0' || g_verbose < 0 || g_verbose > 3)
            {
                fprintf(stderr, "ERROR: --verbose level must be 0-3.\n");
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "ERROR: Unknown option '%s'. Use --help.\n", argv[i]);
            return 1;
        }
    }

    show_banner();

    if (do_upd)
    {
        do_update();
        return 0;
    }

    // ── Administrator check (WinDivert requires kernel access) ────────────────
    if (!is_admin())
    {
        fprintf(stderr, "ERROR: Administrator privileges required.\n");
        fprintf(stderr, "Right-click the executable and select 'Run as administrator'.\n\n");
        return 1;
    }

    if (!profile_path[0])
    {
        fprintf(stderr, "ERROR: No profile specified.\n");
        fprintf(stderr, "Usage: ProxyBridge_CLI.exe --profile <file.pbprofile>\n\n");
        return 1;
    }

    // ── Load profile ──────────────────────────────────────────────────────────
    printf("Loading profile: %s\n", profile_path);
    static PBProfile prof;   // static: with 256 configs the profile is too big for the stack
    if (!load_profile(profile_path, &prof))
        return 1;

    printf("  Proxy configs : %d\n", prof.num_configs);
    printf("  Rules         : %d\n", prof.num_rules);

    if (prof.num_rules == 0)
    {
        fprintf(stderr, "ERROR: Profile contains no rules.\n");
        return 1;
    }

    // ── Load DLL ──────────────────────────────────────────────────────────────
    printf("\nLoading ProxyBridgeCore.dll...\n");
    if (!load_dll()) return 1;
    printf("  DLL loaded.\n");

    // ── Configure callbacks ───────────────────────────────────────────────────
    if (g_verbose == 1 || g_verbose == 3) g_SetLog(log_cb);
    if (g_verbose == 2 || g_verbose == 3) g_SetConn(conn_cb);
    g_SetLocalhost(prof.localhost_via_proxy);
    g_SetTraffic(prof.traffic_logging);

    // ── Push proxy configs + rules into the engine ────────────────────────────
    printf("\nApplying profile:\n");
    sync_profile(&prof, true);
    printf("  %d proxy config(s), %d rule(s) active.\n", g_cfg_n, g_rule_n);

    if (g_rule_n == 0)
    {
        fprintf(stderr, "ERROR: No rules could be applied.\n");
        if (g_Stop) g_Stop();
        FreeLibrary(g_hDll);
        return 1;
    }

    // ── Start ProxyBridge ─────────────────────────────────────────────────────
    printf("\nStarting ProxyBridge...\n");
    if (!g_Start())
    {
        fprintf(stderr, "ERROR: Failed to start.\n");
        fprintf(stderr, "Ensure WinDivert64.sys is present in the same directory.\n");
        FreeLibrary(g_hDll);
        return 1;
    }

    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    InterlockedExchange(&g_running, 1);

    // Remember the profile's current modification time so we can detect edits.
    FILETIME last_write = {0};
    {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExA(profile_path, GetFileExInfoStandard, &fad))
            last_write = fad.ftLastWriteTime;
    }

    printf("ProxyBridge is running. Press Ctrl+C to stop.\n");
    printf("Watching profile for changes - new workers are added live, "
           "without restarting the bridge.\n\n");

    // ── Main loop: stay alive and hot-reload the profile when it changes ──────
    // Polling the mtime (~every 2s) is simple and robust against editors that
    // replace the file atomically. We only ADD new configs/rules, so onboarding
    // a worker never tears down the connections of workers already proxied.
    int tick = 0;
    while (InterlockedCompareExchange(&g_running, 0, 0) != 0)
    {
        Sleep(200);
        if (++tick < 10) continue;   // check roughly every 2 seconds
        tick = 0;

        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (!GetFileAttributesExA(profile_path, GetFileExInfoStandard, &fad))
            continue;                // file briefly missing (atomic replace) - retry
        if (CompareFileTime(&fad.ftLastWriteTime, &last_write) == 0)
            continue;                // unchanged

        Sleep(400);                  // debounce: let the writer finish

        static PBProfile prof2;      // static: too big for the stack
        if (!load_profile(profile_path, &prof2))
            continue;                // mid-write / invalid - keep old mtime, retry

        printf("Profile changed - reloading...\n");
        int changes = sync_profile(&prof2, false);
        last_write = fad.ftLastWriteTime;
        if (changes > 0)
            printf("  %d change%s applied live.\n\n", changes, changes == 1 ? "" : "s");
        else
            printf("  No changes.\n\n");
        fflush(stdout);   // flush now - this is a long-lived, mostly-idle process
    }

    printf("ProxyBridge stopped.\n\n");
    FreeLibrary(g_hDll);
    return 0;
}
