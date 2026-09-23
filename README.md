# SMB_file

**Version : 1.2.0** — voir [CHANGELOG.md](CHANGELOG.md).

Librairie **PlatformIO header-only** (ESP32 / framework Arduino) : client **SMB 2.1 / NTLMv2** pour la **gestion fondamentale de fichiers** sur un partage réseau (NAS Samba/Windows/OMV).

Généraliste et agnostique : aucune dépendance à un format de données (CSV ou autre).

- **Connexion** SMB 2.1 (dialecte `0x0210`) sur TCP 445, authentification **NTLMv2** (SPNEGO + HMAC-MD5), **signature SMB2** (HMAC-SHA256) si le serveur l'exige.
- **Crypto intégrée** (header-only) : MD4, MD5, HMAC-MD5, SHA-256, HMAC-SHA256.
- **Opérations fichier** : création, suppression, existence, dossier, parcours de répertoire, lecture (complète / par morceaux / dernière ligne / tail), écriture, ajout, position/seek.
- **API sync** (bloquante) **et** **file d'attente non bloquante** avec statut (`submit`/`poll`/`status`).
- **Accès multiples** sérialisés par un **mutex récursif**.

---

## 1. Installation

### PlatformIO (recommandé)

Dans le `platformio.ini` du projet consommateur — toujours la forme **git complète** (les libs `Fo170/*` ne sont pas sur le registre PlatformIO) :

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino

lib_deps =
    https://github.com/Fo170/SMB_file.git@^1.2.0
```

### Copie locale

Copier le dossier `lib/SMB_file/` dans le projet PlatformIO (il est découvert automatiquement via `#include <SMB_file.h>`) :

```
lib/SMB_file/
├── library.json
├── library.properties
├── README.md
├── CHANGELOG.md
├── LICENSE
├── keywords.txt
├── src/
│   └── SMB_file.h
└── examples/
    └── SMB_Demo/
        ├── SMB_Demo.ino
        └── platformio.ini
```

```cpp
#include <SMB_file.h>
```

Aucune dépendance `lib_deps` (la librairie n'utilise que `WiFiClient`, `ArduinoJson` non requis, FreeRTOS et `Preferences` non utilisés).

Une macro de version est exposée : `SMB_FILE_VERSION` (`"1.2.0"`) et ses composantes `SMB_FILE_VERSION_MAJOR/MINOR/PATCH`.

---

## 2. Classes

| Classe | Rôle |
|---|---|
| **`SMB_Session`** | Connexion + protocole SMB2 + opérations fichier (sync) + file d'attente async + mutex |
| **`SMB_File`** | Handle d'un fichier **ouvert** (son propre FileId) : `pos`, `seek`, `read`, `write`, `append` |

---

## 3. Démarrage rapide

### Sync (bloquant)

```cpp
SMB_Session smb;
SMB_Config cfg = defaultSMBConfig();      // omv2.local / hdd1 / ProductionSolaire / solar
cfg.host = "192.168.1.209";               // ou "omv2.local"

if (smb.begin(cfg)) {
    smb.mkdir("logs");                     // idempotent
    smb.append("logs/a.csv", "ligne1\r\n"); // crée si absent, sinon ajoute
    smb.writeFile("logs/b.txt", "contenu complet"); // crée/écrase

    // Lecture ligne par ligne (is_header = true pour la 1re ligne)
    smb.readAll("logs/a.csv", [](const char* line, bool is_header) {
        Serial.println(line);
    });

    // Lecture rapide bornée (derniers maxBytes)
    smb.readTail("logs/a.csv", [](const char* l, bool h){ Serial.println(l); }, 2048);

    // Handle de fichier (multi-fichiers)
    SMB_File f;
    if (smb.open(f, "logs/a.csv", SMB_APPEND)) {
        f.write((const uint8_t*)"x", 1);
        f.close();
    }

    // Parcours de répertoire
    smb.listDir("logs", [](const SMB_FileInfo& i){
        Serial.printf("%s (%u o)%s\n", i.name, i.size, i.is_directory ? " [dir]" : "");
    });

    smb.end();
}
```

### Async (non bloquant)

`submit()` met la requête en file ; une **tâche dédiée** appelle `poll()` en boucle ; l'appelant suit le statut.

```cpp
// Producteur (n'importe quelle tâche) :
SMB_Request r = {};
r.type = SMB_REQ_APPEND;
strcpy(r.path, "logs/a.csv");
r.content = "ligne2\r\n";        // ⚠️ doit rester valide jusqu'à DONE
int id = smb.submit(r);          // -1 si la file est pleine

// Tâche dédiée (ex. core 0, basse priorité) :
for (;;) { smb.poll(); vTaskDelay(pdMS_TO_TICKS(50)); }

// Consommateur :
if (smb.status(id) == SMB_DONE && smb.result(id)) { /* OK */ }
smb.release(id);
```

---

## 4. API — `SMB_Session`

### Connexion (sync)

| Méthode | Description |
|---|---|
| `begin(config)` | TCP + NEGOTIATE + SESSION_SETUP (NTLMv2) + TREE_CONNECT |
| `end()` | CLOSE + LOGOFF + fermeture TCP |
| `disconnect()` | coupe le TCP et réinitialise l'état (sans LOGOFF) |
| `isConnected()` / `dialect()` / `lastError()` | état / dialecte négocié / dernière erreur |
| `bytesSent()` / `bytesReceived()` / `errors()` | compteurs de diagnostic |
| `setIOTimeout(ms)` | **timeout I/O par aller-retour** (ms), appliqué dès le prochain `begin()` (`0` = défaut 10000 ms) — évite un blocage trop long |
| `setFeedCallback(cb)` | **callback `void()`** appelé pendant les attentes réseau de `_sendRecv()` (nourrir un WatchDog / un superviseur anti-gel) |

### Fichiers (sync)

| Méthode | Description |
|---|---|
| `open(SMB_File&, path, mode)` | ouvre un fichier (voir `SMB_OpenMode`) |
| `remove(path)` | supprime un fichier |
| `exists(path)` | teste l'existence |
| `mkdir(path)` | crée un dossier (idempotent) |
| `listDir(path, cb)` | parcours de répertoire (`SMB_FileInfo`) |
| `readAll(path, cb, maxBytes=0)` | lecture complète ligne par ligne |
| `readTail(path, cb, maxBytes=4096)` | lecture des derniers `maxBytes` (rapide, bornée) |
| `readLastLine(path, buf, len)` | dernière ligne (reprise d'état) |
| `writeFile(path, content)` | écrit (crée/écrase) |
| `append(path, content)` | ajoute en fin de fichier |
| `syncTime(ntp, tz)` | synchronisation NTP (facultatif) |

### File d'attente non bloquante (async)

| Méthode | Description |
|---|---|
| `submit(req)` | met une requête en file → `id` (≥0) ou -1 |
| `status(id)` | `SMB_IDLE` / `PENDING` / `RUNNING` / `DONE` / `ERROR` |
| `result(id)` / `error(id)` | résultat booléen / message d'erreur |
| `release(id)` | libère le slot |
| `pending()` | nombre de requêtes en file |
| `poll()` | exécute **une** requête (à appeler en boucle par la tâche) |

### Accès multiples

| Méthode | Description |
|---|---|
| `lock()` / `unlock()` | mutex **récursif** (toutes les méthodes publiques le prennent déjà) |

---

## 5. API — `SMB_File`

| Méthode | Description |
|---|---|
| `open(session, path, mode)` | ouvre le handle |
| `close()` | ferme le handle (CLOSE SMB2) |
| `remove()` | supprime le fichier |
| `read(buf, len)` | lit à `pos` → nb d'octets lus (-1 si erreur) |
| `write(buf, len)` | écrit à `pos` → nb écrit (-1 si erreur) |
| `append(buf, len)` | écrit en fin de fichier |
| `seek(pos)` | positionne le curseur |
| `pos()` / `size()` / `eof()` / `isOpen()` / `path()` | accesseurs |

---

## 6. Types & enums

| Type | Valeurs / champs |
|---|---|
| `SMB_Config` | `host`, `share`, `path`, `username`, `password`, `workgroup`, `port`, `use_encryption`, **`io_timeout_ms`** (0 = défaut 10000 ms) |
| `SMB_FileInfo` | `name`, `size`, `modified`, `is_directory` |
| `SMB_OpenMode` | `SMB_READ`, `SMB_WRITE`, `SMB_APPEND`, `SMB_CREATE`, `SMB_CREATE_ALWAYS`, `SMB_OPEN_ALWAYS` |
| `SMB_Status` | `SMB_IDLE`, `SMB_PENDING`, `SMB_RUNNING`, `SMB_DONE`, `SMB_ERROR` |
| `SMB_ReqType` | `SMB_REQ_CONNECT/DISCONNECT/REMOVE/EXISTS/MKDIR/LIST/READALL/READTAIL/WRITEFILE/APPEND` |
| `SMB_LineCallback` | `void(const char* line, bool is_header)` |
| `SMB_ListCallback` | `void(const SMB_FileInfo&)` |
| `defaultSMBConfig()` | config par défaut (`omv2.local` / `hdd1` / `ProductionSolaire`) |

---

## 7. Notes & limites

- **SMB 2.1 uniquement** (dialectes `0x0210` et `0x0202`) — **SMB3 / chiffrement non supportés**. Côté Samba : `server min protocol = SMB2`, `server signing = auto` (ou `no`).
- **Signature SMB2** supportée (HMAC-SHA256) si le serveur l'annonce.
- **I/O bloquantes** : appeler les méthodes sync depuis une **tâche dédiée** (jamais depuis une tâche temps-réel / WDT).
- **Async** : `content` (write/append) doit rester valide jusqu'à `DONE`.
- Les chemins sont **relatifs au partage**, **sans `\` initial** (`dossier/fichier.csv`).
- **Création paresseuse** du mutex/queue FreeRTOS (au premier `begin()`/`lock()`/`submit()`) — jamais en constructeur statique.
- **Correctifs locaux inclus** (par rapport à la version d'origine du projet Production Solaire) :
  1. offsets de parsing RX de l'en-tête SMB2 (`+4` NetBIOS) ;
  2. `end()`/`disconnect()` réinitialisent toute la session ;
  3. `_path()` sans `\` initial ;
  4. masques d'accès + offset du buffer de réponse `4 + DataOffset` ;
  5. **timeout I/O configurable** : `SMB_Config.io_timeout_ms` + `SMB_Session::setIOTimeout(ms)` — l'ancien timeout était **codé en dur à 10 s** par aller-retour, non réglable ;
  6. **`SMB_Session::setFeedCallback(cb)`** : callback `void()` invoqué pendant les attentes de `_sendRecv()` (nourrit WDT/superviseur d'une tâche bloquée sur SMB) ;
  7. ⚠️ **`_write()` découpé en paquets ≤ 3072 o** : avant, tout le contenu était copié dans `_tx[4096]` **sans contrôle de borne** → **débordement silencieux** dès qu'un fichier dépassait ~3,9 Ko (log de crash volumineux). Désormais découpé et transmis en plusieurs trames WRITE.

---

## 8. Exemples

- **Exemple fourni** : [`examples/SMB_Demo/`](examples/SMB_Demo/) (`SMB_Demo.ino` + `platformio.ini`) — connexion WiFi, API sync, handle `SMB_File`, `listDir`, `readAll`/`readTail` et file d'attente asynchrone. Compilation :

  ```bash
  pio run -d examples/SMB_Demo
  ```

- **Usage réel** dans le projet **ESP32 Ordonnanceur** : `src/CSV_reseau.h` (couche métier CSV au-dessus de `SMB_file`) et `src/solar_fct.h` (tâche SMB dédiée).
