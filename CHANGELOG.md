# Changelog

Toutes les dates sont au format AAAA-MM-JJ.
Le versionnage suit [SemVer](https://semver.org/lang/fr/).

## [1.2.1] - 2026-10-17

### ✨ Added — macro de version `__<LIB>_H_VERSION__`

Chaque header déclare désormais sa version via une macro préprocesseur,
source **unique** (un projet hôte peut l'agréger, ex. page `/version`).

### 🏷️ Divers

- Version `1.2.0` → `1.2.1` (`library.json` + `library.properties`)

---

## [1.2.0] - 2026-09-23

Documentation, outillage PlatformIO et exemple — aucun changement d'API ni de
protocole.

- **Ajout** de la macro de version `SMB_FILE_VERSION` (+ `_MAJOR` / `_MINOR` /
  `_PATCH`) dans `src/SMB_file.h`.
- **Ajout** d'un exemple PlatformIO complet `examples/SMB_Demo/`
  (`SMB_Demo.ino` + `platformio.ini`) : connexion WiFi, API sync, handle
  `SMB_File`, `listDir`, `readAll`/`readTail` et file d'attente asynchrone.
- **Ajout** de `library.properties` (PlatformIO / Arduino Library Manager).
- **Ajout** de `CHANGELOG.md`, `keywords.txt` et `LICENSE` (GPL-3.0-only).
- **Enrichissement** des commentaires du `.h` : version, versionnage, mise en
  page de l'en-tête SMB2 (`_hdr`), préfixe NetBIOS dans `_sendRecv`, offsets de
  réponse `CREATE` / `READ` / `QUERY_DIRECTORY`.
- **Mise à jour** de `library.json` (métadonnées complètes, `repository`,
  `homepage`, `examples`, `export.exclude`) et du `README.md`.

## [1.1.0] - 2026

Correctifs locaux par rapport à la version d'origine (projet Production Solaire) :

- Parsing RX de l'en-tête SMB2 décalé de 4 o (préfixe NetBIOS).
- `end()` / `disconnect()` réinitialisent tout l'état de session.
- `_path()` sans backslash initial ; masques d'accès corrigés.
- Offset du buffer de réponse = `4 + DataOffset`.
- **Timeout I/O configurable** : `SMB_Config.io_timeout_ms` +
  `SMB_Session::setIOTimeout(ms)` (défaut 10000 ms).
- **`SMB_Session::setFeedCallback(cb)`** : callback `void()` invoqué pendant
  `_sendRecv()` pour nourrir un WatchDog / superviseur.
- **`_write()` découpé en paquets ≤ 3072 o** : corrige un débordement silencieux
  de `_tx[4096]` pour un fichier > ~3,9 Ko.

## [1.0.0] - 2026

Version initiale : client SMB 2.1 / NTLMv2, opérations fichier sync, file
d'attente asynchrone et crypto intégrée.
