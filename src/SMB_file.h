/**
 * @file SMB_file.h
 * @brief Client SMB2.1 / CIFS générique (ESP32) — gestion fondamentale de fichiers
 * @version 1.2.0
 * @author Olivier FOURNET <olivier.fournet@free.fr>
 * @copyright GPL-3.0-only
 * @see https://github.com/Fo170/SMB_file
 *
 * Généraliste et agnostique au projet : aucune notion de CSV.
 *
 * Protocole : SMB 2.1 (dialecte 0x0210) sur TCP 445
 * Authentification : NTLMv2 (SPNEGO + HMAC-MD5)
 * Crypto intégrée (header-only) : MD4 (NT hash), MD5, HMAC-MD5, SHA-256, HMAC-SHA256
 *
 * Portée :
 *   - SMB_Session : connexion + protocole + opérations fichier (sync) + file
 *     d'attente non bloquante avec statut (async) + accès multiples (mutex).
 *   - SMB_File    : handle de fichier (nom, chemin, pos, seek, read, write, append).
 *
 * Voir le dossier `examples/SMB_Demo/` pour un sketch PlatformIO complet, et le
 * `README.md` / `CHANGELOG.md` pour l'API détaillée et l'historique.
 *
 * Exemple (sync) :
 *   SMB_Session smb;
 *   SMB_Config cfg = defaultSMBConfig();
 *   if (smb.begin(cfg)) {
 *     smb.append("logs/a.csv", "ligne1\r\n");
 *     smb.readTail("logs/a.csv", [](const char* l, bool h){ Serial.println(l); }, 2048);
 *     SMB_File f;
 *     if (smb.open(f, "logs/a.csv", SMB_READ)) { uint8_t buf[64]; f.read(buf, 64); f.close(); }
 *   }
 *
 * Exemple (async, non bloquant) — une tâche appelle poll() en boucle :
 *   SMB_Request r = {}; r.type = SMB_REQ_APPEND;
 *   strcpy(r.path, "logs/a.csv"); r.content = "ligne2\r\n";
 *   int id = smb.submit(r);
 *   while (smb.status(id) == SMB_PENDING || smb.status(id) == SMB_RUNNING) { smb.poll(); delay(1); }
 *   smb.release(id);
 *
 * ⚠️ Signature SMB2 et chiffrement SMB3 NON supportés.
 *    Configurer Samba avec : server signing = auto (ou no) et server min protocol = SMB2
 *
 * ⚠️ Correctifs locaux par rapport à la version d'origine (projet Production Solaire) :
 *   (1) offsets de parsing RX de l'en-tête SMB2 décalés de 4 o (en-tête NetBIOS) ;
 *   (2) end()/disconnect() réinitialisent tout l'état de session ;
 *   (3) _path() sans backslash initial ;
 *   (4) masques d'accès appendLine/ensureDirectory ;
 *   (5) offset du buffer de réponse = 4 + DataOffset (et non 68 + DataOffset).
 *
 * ⚠️ Ajouts locaux (2026) :
 *   (6) TIMEOUT I/O CONFIGURABLE : `SMB_Config.io_timeout_ms` + `SMB_Session::setIOTimeout(ms)`
 *       (défaut 10000 ms) — l'ancien timeout était codé en dur à 10 s par aller-retour ;
 *   (7) `SMB_Session::setFeedCallback(cb)` : callback void() appelé pendant les attentes
 *       de `_sendRecv()` → permet de nourrir un WatchDog / superviseur anti-gel pendant
 *       une opération SMB bloquante ;
 *   (8) `_write()` DÉCOUPÉ en paquets ≤ 3072 o : auparavant tout le contenu était copié
 *       dans `_tx[4096]` SANS contrôle de borne → débordement silencieux pour un fichier
 *       > ~3,9 Ko. Désormais transmis en plusieurs trames WRITE.
 */

#ifndef SMB_FILE_H
#define SMB_FILE_H

// ----------------------------------------------------------------------------
// Version de la librairie
// ----------------------------------------------------------------------------
// ⚠️ À synchroniser avec library.json, library.properties, README.md et
//    CHANGELOG.md à chaque montée de version.
#define SMB_FILE_VERSION       "1.2.0"
#define SMB_FILE_VERSION_MAJOR 1
#define SMB_FILE_VERSION_MINOR 2
#define SMB_FILE_VERSION_PATCH 0

#include <Arduino.h>
#include <WiFiClient.h>
#include <functional>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>

#define SMB_PORT 445          // port TCP standard SMB direct (pas de NetBIOS 139)
#define SMB_MAX_PAYLOAD 4096  // taille des tampons de trame _tx / _rx (octets)

// SMB2 commands
#define SMB2_NEGOTIATE       0x0000
#define SMB2_SESSION_SETUP   0x0001
#define SMB2_LOGOFF          0x0002
#define SMB2_TREE_CONNECT    0x0003
#define SMB2_TREE_DISCONNECT 0x0004
#define SMB2_CREATE          0x0005
#define SMB2_CLOSE           0x0006
#define SMB2_FLUSH           0x0007
#define SMB2_READ            0x0008
#define SMB2_WRITE           0x0009
#define SMB2_SET_INFO        0x000B
#define SMB2_QUERY_DIRECTORY 0x000E

// NT Status
#define SMB2_STATUS_SUCCESS              0x00000000
#define SMB2_STATUS_MORE_PROCESSING      0xC0000016
#define SMB2_STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#define SMB2_STATUS_NO_MORE_FILES         0x80000006
#define SMB2_STATUS_END_OF_FILE           0xC0000011
#define SMB2_STATUS_OBJECT_NAME_COLLISION 0xC0000035
#define SMB2_STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------
struct SMB_Config {
  char host[64];        // Nom ou IP (ex: "omv2.local")
  char share[64];       // Nom partage (ex: "hdd1")
  char path[128];       // Chemin dans le partage (ex: "ProductionSolaire")
  char username[32];
  char password[32];
  char workgroup[16];   // Domaine/Workgroup
  uint16_t port;
  bool use_encryption;
  uint32_t io_timeout_ms;   // timeout I/O par aller-retour (0 = défaut 10000 ms)
};

// Info fichier (listing de répertoire)
struct SMB_FileInfo {
  char name[128];
  uint32_t size;
  time_t modified;
  bool is_directory;
};

typedef std::function<void(const char* line, bool is_header)> SMB_LineCallback;
typedef std::function<void(const SMB_FileInfo& info)> SMB_ListCallback;

// Modes d'ouverture d'un fichier
enum SMB_OpenMode {
  SMB_READ,           // ouvre en lecture (doit exister)
  SMB_WRITE,          // ouvre en écriture (crée si absent)
  SMB_APPEND,         // ouvre et se place en fin de fichier
  SMB_CREATE,         // crée (échoue si existe déjà)
  SMB_CREATE_ALWAYS,  // crée ou écrase
  SMB_OPEN_ALWAYS     // ouvre ou crée
};

// Statut d'une requête asynchrone
// Statut d'une requête asynchrone (voir SMB_Session::submit/status)
enum SMB_Status {
  SMB_IDLE = 0,   // slot libre / jamais utilisé
  SMB_PENDING,    // en file d'attente
  SMB_RUNNING,    // en cours d'exécution (dans poll())
  SMB_DONE,       // terminée avec succès
  SMB_ERROR       // terminée en échec (voir error(id))
};

// Type de requête asynchrone (fondamentale) — voir SMB_Session::submit()
enum SMB_ReqType {
  SMB_REQ_NONE = 0,
  SMB_REQ_CONNECT,      // (re)connexion avec la config courante
  SMB_REQ_DISCONNECT,   // fermeture de la session
  SMB_REQ_REMOVE,       // suppression de fichier
  SMB_REQ_EXISTS,       // test d'existence
  SMB_REQ_MKDIR,        // création de dossier
  SMB_REQ_LIST,         // parcours de répertoire
  SMB_REQ_READALL,      // lecture complète (lignes)
  SMB_REQ_READTAIL,     // lecture des derniers maxBytes
  SMB_REQ_WRITEFILE,    // écriture (création/écrasement)
  SMB_REQ_APPEND        // ajout en fin de fichier
};

// Requête soumise à la file d'attente non bloquante.
// ⚠️ `content` (writeFile/append) doit rester valide jusqu'à ce que le statut
//    passe à SMB_DONE/SMB_ERROR (la requête est copiée par valeur mais le
//    pointeur de contenu, lui, n'est pas recopié).
struct SMB_Request {
  SMB_ReqType type;       // opération demandée
  SMB_Status  status;     // statut courant (rempli par la file)
  char        path[160];  // chemin relatif au partage (sans '\' initial)
  size_t      maxBytes;   // pour SMB_REQ_READALL / SMB_REQ_READTAIL (0 = tout)
  const char* content;    // pour SMB_REQ_WRITEFILE / SMB_REQ_APPEND (C-string)
  bool        result;     // résultat (true = succès)
  String      error;      // message d'erreur si result == false
};

class SMB_Session;

// ============================================================================
// SMB_File : handle de fichier (nom, chemin, position, seek, read, write, append)
// ----------------------------------------------------------------------------
// Représente un fichier OUVERT (son propre FileId SMB2 → plusieurs fichiers
// peuvent être ouverts simultanément). Toutes les opérations passent par la
// session associée (thread-safe via le mutex de la session).
// ============================================================================
class SMB_File {
public:
  SMB_File() : _s(nullptr), _open(false), _pos(0), _size(0) { _path[0] = '\0'; memset(_file_id, 0, 16); }

  bool isOpen() const { return _open; }        // fichier ouvert ?
  const char* path() const { return _path; }   // chemin (relatif au partage)
  uint64_t pos() const { return _pos; }        // position courante (octets)
  uint64_t size() const { return _size; }      // taille connue (octets)
  bool eof() const { return _pos >= _size; }   // fin de fichier atteinte ?

  bool open(SMB_Session* s, const char* path, SMB_OpenMode mode = SMB_READ);
  void close();                                // ferme le handle (CLOSE SMB2)
  bool remove();                               // supprime le fichier

  int  read(uint8_t* buf, size_t len);         // lit → nb d'octets lus, -1 si erreur
  int  write(const uint8_t* buf, size_t len);  // écrit à pos → nb écrit, -1 si erreur
  int  append(const uint8_t* buf, size_t len); // écrit en fin de fichier
  bool seek(uint64_t pos);                     // positionne le curseur

private:
  friend class SMB_Session;   // la session peut manipuler le FileId interne
  SMB_Session* _s;            // session propriétaire (nullptr si non ouvert)
  bool     _open;
  char     _path[160];
  uint64_t _pos;              // position de lecture/écriture
  uint64_t _size;             // taille au moment de l'ouverture / après écriture
  uint8_t  _file_id[16];      // FileId SMB2 (persistent + volatile)
};

// ============================================================================
// SMB_Session : connexion SMB2.1 + opérations fichier (sync) + file
//               d'attente non bloquante (async) + accès multiples (mutex)
// ----------------------------------------------------------------------------
// Toutes les méthodes publiques prennent le mutex interne (récursif) : elles
// sont donc sûres depuis plusieurs tâches. Les I/O étant bloquantes, elles
// doivent être appelées depuis une tâche dédiée (ex. Task_SMB) et non depuis
// une tâche temps-réel.
// ============================================================================
#define SMB_REQ_SLOTS 8   // nb de requêtes asynchrones simultanées max

class SMB_Session {
public:
  SMB_Session();
  ~SMB_Session();

  // --- Connexion (sync) ---
  bool begin(const SMB_Config& config);   // TCP + NEGOTIATE + NTLMv2 + TREE_CONNECT
  void end();                             // CLOSE/LOGOFF puis fermeture TCP
  void disconnect();                      // coupe le TCP + reset état (sans LOGOFF)
  bool isConnected() const { return _connected; }
  uint16_t dialect() const { return _dialect; }        // 0x0210 (2.1) ou 0x0202
  String lastError() const { return _last_error; }     // dernier message d'erreur
  uint32_t bytesSent() const { return _bytes_sent; }   // compteur d'octets émis
  uint32_t bytesReceived() const { return _bytes_received; }
  uint32_t errors() const { return _errors; }

  // --- Fichiers (sync) ---
  bool open(SMB_File& f, const char* path, SMB_OpenMode mode = SMB_READ);
  bool remove(const char* path);          // supprime un fichier
  bool exists(const char* path);          // teste l'existence
  bool mkdir(const char* path);           // crée un dossier (idempotent)
  bool listDir(const char* path, SMB_ListCallback callback);  // parcours répertoire

  // --- Flux (sync) ---
  // readAll/readTail : callbacks ligne par ligne (is_header=true pour l'en-tête).
  bool readAll(const char* path, SMB_LineCallback cb, size_t maxBytes = 0);
  bool readTail(const char* path, SMB_LineCallback cb, size_t maxBytes = 4096);
  bool readLastLine(const char* path, char* buffer, size_t buflen);
  bool writeFile(const char* path, const String& content);  // crée/écrase
  bool append(const char* path, const String& content);     // ajoute en fin

  bool syncTime(const char* ntp_server = "pool.ntp.org", int timezone_offset = 3600);

  // --- File d'attente non bloquante (async) ---
  // submit() copie la requête dans un slot libre et la met en file ; la tâche
  // applicative appelle poll() pour exécuter UNE requête ; l'appelant suit
  // l'avancement via status()/result()/error(), puis release() le slot.
  int        submit(const SMB_Request& req);   // -> id (>=0) ou -1 si plein
  SMB_Status status(int id) const;             // statut du slot
  bool       result(int id) const;             // résultat (true = succès)
  String     error(int id) const;              // message d'erreur
  void       release(int id);                  // libère le slot
  int        pending() const;                  // nb de requêtes en file
  void       poll();                           // traite UNE requête (à appeler en boucle)

  // --- Accès multiples ---
  void lock();     // prend le mutex récursif (bloquant)
  void unlock();   // relâche le mutex

  // --- Config ---
  const SMB_Config& config() const { return _config; }

  // --- Réglages runtime ---
  // Timeout I/O par aller-retour (ms) appliqué dès le prochain begin().
  void setIOTimeout(uint32_t ms) { _io_timeout_ms = ms ? ms : 10000; }
  // Callback appelé pendant les attentes réseau (nourrir WDT/superviseur).
  void setFeedCallback(std::function<void()> cb) { _feed_cb = cb; }

private:
  friend class SMB_File;

  // --- État de session / transport ---
  SMB_Config _config;            // config courante
  WiFiClient _client;            // socket TCP (port 445)
  bool _connected;               // session établie (NEGOTIATE+SESSION+TREE OK)
  uint64_t _session_id;          // SessionId SMB2
  uint32_t _tree_id;             // TreeId SMB2 (partage)
  uint8_t  _file_id[16];         // fichier "courant" pour les ops de transport
  uint64_t _file_size;           // taille du fichier courant (EndOfFile)
  uint64_t _message_id;          // MessageId SMB2 (incrémenté)
  uint16_t _credits;             // crédits SMB2 accordés par le serveur
  uint16_t _dialect;             // dialecte négocié (0x0210 / 0x0202)
  uint8_t  _session_key[16];     // SessionBaseKey (signature SMB2)
  bool     _signing_active;      // signature SMB2 active (si serveur l'exige)
  bool     _server_signing;      // le serveur annonce la signature
  uint32_t _bytes_sent;          // compteurs (diagnostic)
  uint32_t _bytes_received;
  uint32_t _errors;
  String   _last_error;          // dernier message d'erreur
  uint32_t _io_timeout_ms;       // timeout I/O par aller-retour (ms)
  std::function<void()> _feed_cb; // rafraîchissement WDT/superviseur (optionnel)

  // --- Tampons de trame (TX/RX) ---
  uint8_t _rx[SMB_MAX_PAYLOAD];
  uint8_t _tx[SMB_MAX_PAYLOAD];
  size_t _rx_len;
  size_t _tx_len;

  // --- File d'attente asynchrone ---
  QueueHandle_t _queue;          // file d'index de slots (int8_t)
  SemaphoreHandle_t _mtx;        // mutex récursif (accès multiples)
  SMB_Request _slots[SMB_REQ_SLOTS];
  bool _slotUsed[SMB_REQ_SLOTS];

  // --- Handshake SMB2 ---
  bool _negotiate();             // NEGOTIATE (dialectes 2.1 / 2.0.2)
  bool _sessionSetup();          // SESSION_SETUP (SPNEGO + NTLMv2 Type1/2/3)
  bool _treeConnect();           // TREE_CONNECT (\\hôte\partage)
  bool _logoff();                // LOGOFF

  // --- Opérations fichier bas niveau (le FileId courant est _file_id) ---
  bool _create(const char* path, uint32_t desired_access, uint32_t create_disp,
               uint32_t create_options, bool directory);
  bool _close();
  bool _write(const uint8_t* data, size_t len, uint64_t offset);
  bool _read(uint8_t* buffer, size_t max_len, uint64_t offset, size_t& bytes_read);
  bool _queryDir(const char* path, SMB_ListCallback callback);
  bool _setDelete();

  // --- Transport (construction/lecture de la trame SMB2) ---
  void _hdr(uint16_t command, uint16_t credit_charge = 1);   // en-tête SMB2
  bool _sendRecv(uint32_t& status, uint16_t& resp_cmd);      // envoi + réception
  void _put8(size_t& p, uint8_t v);
  void _put16(size_t& p, uint16_t v);
  void _put32(size_t& p, uint32_t v);
  void _put64(size_t& p, uint64_t v);
  void _putBytes(size_t& p, const void* d, size_t n);
  uint16_t _get16(size_t p) const;
  uint32_t _get32(size_t p) const;
  uint64_t _get64(size_t p) const;
  String _path(const char* rel) const;   // chemin relatif (sans '\' initial)
  String _unc() const;                    // \\hôte\partage

  uint32_t _modeAccess(SMB_OpenMode m) const;        // SMB_OpenMode -> DesiredAccess
  uint32_t _modeDisposition(SMB_OpenMode m) const;   // SMB_OpenMode -> CreateDisposition
  void _ensureInit();                                // création paresseuse mutex/queue
};

// ============================================================================
// CRYPTO (MD4, MD5, HMAC-MD5, NTLMv2, SHA-256, HMAC-SHA256)
// ============================================================================
namespace SMBcrypto {

inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

// ------------------------------ MD4 ------------------------------
struct MD4Ctx { uint32_t s[4]; uint64_t count; uint8_t buf[64]; };
inline void md4Init(MD4Ctx* c) {
  c->s[0]=0x67452301; c->s[1]=0xEFCDAB89; c->s[2]=0x98BADCFE; c->s[3]=0x10325476; c->count=0;
}
inline void md4Block(uint32_t s[4], const uint8_t b[64]) {
  uint32_t a=s[0],bb=s[1],c=s[2],d=s[3],x[16];
  for(int i=0;i<16;i++) x[i]=(uint32_t)b[i*4]|((uint32_t)b[i*4+1]<<8)|((uint32_t)b[i*4+2]<<16)|((uint32_t)b[i*4+3]<<24);
  #define MD4F(x,y,z) (((x)&(y))|(~(x)&(z)))
  #define MD4G(x,y,z) (((x)&(y))|((x)&(z))|((y)&(z)))
  #define MD4H(x,y,z) ((x)^(y)^(z))
  #define R1(a,b,c,d,k,sh) a=rotl32(a+MD4F(b,c,d)+x[k],sh)
  #define R2(a,b,c,d,k,sh) a=rotl32(a+MD4G(b,c,d)+x[k]+0x5A827999,sh)
  #define R3(a,b,c,d,k,sh) a=rotl32(a+MD4H(b,c,d)+x[k]+0x6ED9EBA1,sh)
  R1(a,bb,c,d,0,3);R1(d,a,bb,c,1,7);R1(c,d,a,bb,2,11);R1(bb,c,d,a,3,19);
  R1(a,bb,c,d,4,3);R1(d,a,bb,c,5,7);R1(c,d,a,bb,6,11);R1(bb,c,d,a,7,19);
  R1(a,bb,c,d,8,3);R1(d,a,bb,c,9,7);R1(c,d,a,bb,10,11);R1(bb,c,d,a,11,19);
  R1(a,bb,c,d,12,3);R1(d,a,bb,c,13,7);R1(c,d,a,bb,14,11);R1(bb,c,d,a,15,19);
  R2(a,bb,c,d,0,3);R2(d,a,bb,c,4,5);R2(c,d,a,bb,8,9);R2(bb,c,d,a,12,13);
  R2(a,bb,c,d,1,3);R2(d,a,bb,c,5,5);R2(c,d,a,bb,9,9);R2(bb,c,d,a,13,13);
  R2(a,bb,c,d,2,3);R2(d,a,bb,c,6,5);R2(c,d,a,bb,10,9);R2(bb,c,d,a,14,13);
  R2(a,bb,c,d,3,3);R2(d,a,bb,c,7,5);R2(c,d,a,bb,11,9);R2(bb,c,d,a,15,13);
  R3(a,bb,c,d,0,3);R3(d,a,bb,c,8,9);R3(c,d,a,bb,4,11);R3(bb,c,d,a,12,15);
  R3(a,bb,c,d,2,3);R3(d,a,bb,c,10,9);R3(c,d,a,bb,6,11);R3(bb,c,d,a,14,15);
  R3(a,bb,c,d,1,3);R3(d,a,bb,c,9,9);R3(c,d,a,bb,5,11);R3(bb,c,d,a,13,15);
  R3(a,bb,c,d,3,3);R3(d,a,bb,c,11,9);R3(c,d,a,bb,7,11);R3(bb,c,d,a,15,15);
  s[0]+=a;s[1]+=bb;s[2]+=c;s[3]+=d;
  #undef MD4F
  #undef MD4G
  #undef MD4H
  #undef R1
  #undef R2
  #undef R3
}
inline void md4Update(MD4Ctx* c, const uint8_t* d, size_t n) {
  size_t i=(size_t)(c->count&63); c->count+=n; size_t part=64-i, k=0;
  if(n>=part){ memcpy(&c->buf[i],d,part); md4Block(c->s,c->buf);
    for(k=part;k+63<n;k+=64){ md4Block(c->s,&d[k]); }
    i=0; }
  memcpy(&c->buf[i],&d[k],n-k);
}
inline void md4Final(MD4Ctx* c, uint8_t out[16]) {
  uint8_t bits[8]; uint64_t cnt=c->count*8;
  for(int i=0;i<8;i++) bits[i]=(uint8_t)(cnt>>(8*i));
  static const uint8_t pad[64]={0x80};
  size_t padlen=((c->count%64)<56)?(56-c->count%64):(120-c->count%64);
  md4Update(c,pad,padlen); md4Update(c,bits,8);
  for(int i=0;i<4;i++){ out[i*4]=c->s[i]&0xFF; out[i*4+1]=(c->s[i]>>8)&0xFF;
    out[i*4+2]=(c->s[i]>>16)&0xFF; out[i*4+3]=(c->s[i]>>24)&0xFF; }
}

// ------------------------------ MD5 ------------------------------
struct MD5Ctx { uint32_t s[4]; uint64_t count; uint8_t buf[64]; };
static const uint32_t MD5K[64]={
  0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
  0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
  0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
  0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
  0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
  0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
  0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
  0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
static const uint8_t MD5R[64]={
  7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
  5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
  4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
  6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
inline void md5Init(MD5Ctx* c) {
  c->s[0]=0x67452301;c->s[1]=0xefcdab89;c->s[2]=0x98badcfe;c->s[3]=0x10325476;c->count=0;
}
inline void md5Block(uint32_t s[4], const uint8_t b[64]) {
  uint32_t m[16];
  for(int i=0;i<16;i++) m[i]=(uint32_t)b[i*4]|((uint32_t)b[i*4+1]<<8)|((uint32_t)b[i*4+2]<<16)|((uint32_t)b[i*4+3]<<24);
  uint32_t a=s[0],bb=s[1],c=s[2],d=s[3];
  for(int i=0;i<64;i++){
    uint32_t f; int g;
    if(i<16){ f=(bb&c)|(~bb&d); g=i; }
    else if(i<32){ f=(d&bb)|(~d&c); g=(5*i+1)%16; }
    else if(i<48){ f=bb^c^d; g=(3*i+5)%16; }
    else { f=c^(bb|~d); g=(7*i)%16; }
    uint32_t tmp=d; d=c; c=bb;
    bb=bb+rotl32(a+f+MD5K[i]+m[g],MD5R[i]);
    a=tmp;
  }
  s[0]+=a;s[1]+=bb;s[2]+=c;s[3]+=d;
}
inline void md5Update(MD5Ctx* c, const uint8_t* d, size_t n) {
  size_t i=(size_t)(c->count&63); c->count+=n; size_t part=64-i,k=0;
  if(n>=part){ memcpy(&c->buf[i],d,part); md5Block(c->s,c->buf);
    for(k=part;k+63<n;k+=64){ md5Block(c->s,&d[k]); }
    i=0; }
  memcpy(&c->buf[i],&d[k],n-k);
}
inline void md5Final(MD5Ctx* c, uint8_t out[16]) {
  uint8_t bits[8]; uint64_t cnt=c->count*8;
  for(int i=0;i<8;i++) bits[i]=(uint8_t)(cnt>>(8*i));
  static const uint8_t pad[64]={0x80};
  size_t padlen=((c->count%64)<56)?(56-c->count%64):(120-c->count%64);
  md5Update(c,pad,padlen); md5Update(c,bits,8);
  for(int i=0;i<4;i++){ out[i*4]=c->s[i]&0xFF; out[i*4+1]=(c->s[i]>>8)&0xFF;
    out[i*4+2]=(c->s[i]>>16)&0xFF; out[i*4+3]=(c->s[i]>>24)&0xFF; }
}
inline void md5(const uint8_t* d, size_t n, uint8_t out[16]) {
  MD5Ctx c; md5Init(&c); md5Update(&c,d,n); md5Final(&c,out);
}

// --------------------------- HMAC-MD5 ----------------------------
inline void hmacMd5(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t out[16]) {
  uint8_t k[64]; memset(k,0,64);
  if(keyLen>64) md5(key,keyLen,k); else memcpy(k,key,keyLen);
  uint8_t ipad[64],opad[64];
  for(int i=0;i<64;i++){ ipad[i]=k[i]^0x36; opad[i]=k[i]^0x5c; }
  MD5Ctx c; uint8_t inner[16];
  md5Init(&c); md5Update(&c,ipad,64); md5Update(&c,data,dataLen); md5Final(&c,inner);
  md5Init(&c); md5Update(&c,opad,64); md5Update(&c,inner,16); md5Final(&c,out);
}

// ------------------------- UTF-16LE ------------------------------
inline void toUTF16LE(const char* s, uint8_t* out, size_t& len) {
  len=0; while(*s){ out[len++]=(uint8_t)*s++; out[len++]=0; }
}
inline void toUTF16LEUpper(const char* s, uint8_t* out, size_t& len) {
  len=0; while(*s){ char c=*s++; if(c>='a'&&c<='z') c-=32; out[len++]=(uint8_t)c; out[len++]=0; }
}

// ------------------------- NTLMv2 --------------------------------
inline void ntHash(const char* password, uint8_t hash[16]) {
  uint8_t u[256]; size_t n; toUTF16LE(password,u,n);
  MD4Ctx c; md4Init(&c); md4Update(&c,u,n); md4Final(&c,hash);
}
inline void ntlmv2Hash(const uint8_t ntHash[16], const char* user, const char* domain, uint8_t out[16]) {
  uint8_t id[512]; size_t idLen=0;
  toUTF16LEUpper(user, id, idLen);
  size_t dl=0; toUTF16LE(domain, id+idLen, dl); idLen+=dl;
  hmacMd5(ntHash, 16, id, idLen, out);
}

// ------------------------------ SHA-256 ------------------------------
struct SHA256Ctx { uint32_t s[8]; uint64_t count; uint8_t buf[64]; };
static const uint32_t SHA256K[64]={
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
inline uint32_t rotr32(uint32_t x,int n){ return (x>>n)|(x<<(32-n)); }
inline void sha256Block(uint32_t s[8], const uint8_t b[64]){
  uint32_t w[64];
  for(int i=0;i<16;i++) w[i]=(uint32_t)b[i*4]<<24|(uint32_t)b[i*4+1]<<16|(uint32_t)b[i*4+2]<<8|b[i*4+3];
  for(int i=16;i<64;i++){
    uint32_t s0=rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3);
    uint32_t s1=rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10);
    w[i]=w[i-16]+s0+w[i-7]+s1;
  }
  uint32_t a=s[0],bb=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
  for(int i=0;i<64;i++){
    uint32_t S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
    uint32_t ch=(e&f)^(~e&g);
    uint32_t t1=h+S1+ch+SHA256K[i]+w[i];
    uint32_t S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
    uint32_t maj=(a&bb)^(a&c)^(bb&c);
    uint32_t t2=S0+maj;
    h=g;g=f;f=e;e=d+t1;d=c;c=bb;bb=a;a=t1+t2;
  }
  s[0]+=a;s[1]+=bb;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
inline void sha256Init(SHA256Ctx* c){
  c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;c->s[3]=0xa54ff53a;
  c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;c->count=0;
}
inline void sha256Update(SHA256Ctx* c,const uint8_t* d,size_t n){
  size_t i=(size_t)(c->count&63); c->count+=n; size_t part=64-i,k=0;
  if(n>=part){ memcpy(&c->buf[i],d,part); sha256Block(c->s,c->buf);
    for(k=part;k+63<n;k+=64){ sha256Block(c->s,&d[k]); }
    i=0; }
  memcpy(&c->buf[i],&d[k],n-k);
}
inline void sha256Final(SHA256Ctx* c,uint8_t out[32]){
  uint8_t bits[8]; uint64_t cnt=c->count*8;
  for(int i=0;i<8;i++) bits[i]=(uint8_t)(cnt>>(56-8*i));
  static const uint8_t pad[64]={0x80};
  size_t padlen=((c->count%64)<56)?(56-c->count%64):(120-c->count%64);
  sha256Update(c,pad,padlen); sha256Update(c,bits,8);
  for(int i=0;i<8;i++){ out[i*4]=c->s[i]>>24; out[i*4+1]=c->s[i]>>16; out[i*4+2]=c->s[i]>>8; out[i*4+3]=c->s[i]; }
}
inline void sha256(const uint8_t* d,size_t n,uint8_t out[32]){
  SHA256Ctx c; sha256Init(&c); sha256Update(&c,d,n); sha256Final(&c,out);
}
inline void hmacSha256(const uint8_t* key,size_t keyLen,const uint8_t* data,size_t dataLen,uint8_t out[32]){
  uint8_t k[64]; memset(k,0,64);
  if(keyLen>64) sha256(key,keyLen,k); else memcpy(k,key,keyLen);
  uint8_t ipad[64],opad[64];
  for(int i=0;i<64;i++){ ipad[i]=k[i]^0x36; opad[i]=k[i]^0x5c; }
  SHA256Ctx c; uint8_t inner[32];
  sha256Init(&c); sha256Update(&c,ipad,64); sha256Update(&c,data,dataLen); sha256Final(&c,inner);
  sha256Init(&c); sha256Update(&c,opad,64); sha256Update(&c,inner,32); sha256Final(&c,out);
}

} // namespace SMBcrypto

// ============================================================================
// IMPLÉMENTATION
// ============================================================================

// Encodeur de longueur DER (ASN.1) : tag + longueur (1/2/3 octets)
static inline size_t smbDerPut(uint8_t* buf, size_t pos, uint8_t tag, size_t len) {
  buf[pos++] = tag;
  if (len < 0x80) {
    buf[pos++] = (uint8_t)len;
  } else if (len < 0x100) {
    buf[pos++] = 0x81; buf[pos++] = (uint8_t)len;
  } else {
    buf[pos++] = 0x82; buf[pos++] = (uint8_t)(len >> 8); buf[pos++] = (uint8_t)(len & 0xFF);
  }
  return pos;
}

inline SMB_Session::SMB_Session() : _connected(false), _session_id(0), _tree_id(0),
  _file_size(0), _message_id(0), _credits(1), _dialect(0),
  _signing_active(false), _server_signing(false),
  _bytes_sent(0), _bytes_received(0), _errors(0), _io_timeout_ms(10000),
  _rx_len(0), _tx_len(0),
  _queue(nullptr), _mtx(nullptr) {
  memset(_file_id,0,16);
  memset(_session_key,0,16);
  for (int i = 0; i < SMB_REQ_SLOTS; i++) { _slotUsed[i] = false; _slots[i].status = SMB_IDLE; }
  _last_error = "Non initialisé";
}

inline SMB_Session::~SMB_Session() { end(); }

// Création paresseuse des objets FreeRTOS (jamais en constructeur statique).
inline void SMB_Session::_ensureInit() {
  if (!_mtx)   _mtx   = xSemaphoreCreateRecursiveMutex();
  if (!_queue) _queue = xQueueCreate(SMB_REQ_SLOTS, sizeof(int8_t));
}

inline void SMB_Session::lock() { _ensureInit(); if (_mtx) xSemaphoreTakeRecursive(_mtx, portMAX_DELAY); }
inline void SMB_Session::unlock() { if (_mtx) xSemaphoreGiveRecursive(_mtx); }

inline void SMB_Session::end() {
  lock();
  if (_connected) { _close(); _logoff(); }
  unlock();
  disconnect();
}

// Coupe la connexion TCP et réinitialise l'état de session SANS LOGOFF.
inline void SMB_Session::disconnect() {
  lock();
  _client.stop();
  _connected = false;
  // ⚠️ Réinitialise TOUT l'état : sinon un NEGOTIATE ultérieur part avec un
  // SessionId/TreeId périmés et le serveur rejette la trame.
  _session_id = 0;
  _tree_id = 0;
  _message_id = 0;
  _dialect = 0;
  _signing_active = false;
  _server_signing = false;
  _rx_len = 0;
  _tx_len = 0;
  memset(_file_id, 0, 16);
  memset(_session_key, 0, 16);
  unlock();
}

inline bool SMB_Session::begin(const SMB_Config& config) {
  lock();
  _config = config;
  if (_config.io_timeout_ms) _io_timeout_ms = _config.io_timeout_ms;   // 0 = conserver le réglage
  if (_io_timeout_ms == 0) _io_timeout_ms = 10000;
  if (_connected) { _close(); _logoff(); }
  _client.stop();
  _connected = false;
  _session_id = 0; _tree_id = 0; _message_id = 0; _dialect = 0;
  _signing_active = false; _server_signing = false; _rx_len = 0; _tx_len = 0;
  memset(_file_id, 0, 16); memset(_session_key, 0, 16);

  if (!_client.connect(_config.host, _config.port)) {
    _last_error = "Echec TCP " + String(_config.host) + ":" + String(_config.port);
    _errors++; unlock(); return false;
  }
  _client.setTimeout((_io_timeout_ms + 999) / 1000);
  bool ok = _negotiate() && _sessionSetup() && _treeConnect();
  if (ok) {
    _connected = true;
    _last_error = "Connecté (SMB " + String(_dialect == 0x0210 ? "2.1" : "2.0.2") + ")";
  }
  unlock();
  return ok;
}

// ------------------------------ Header SMB2 ------------------------------
// Construit l'en-tête SMB2 (64 o) au début de _tx, précédé du préfixe NetBIOS
// de 4 o (RFC 1002 « Direct TCP transport ») :
//
//   [0..3]   préfixe NetBIOS (longueur SMB, écrite dans _sendRecv)
//   [4..7]   signature "\xFE" 'S' 'M' 'B'
//   [8..9]   StructureSize = 64
//   [10..11] CreditCharge
//   [12..15] Status / ChannelSequence (0 en requête)
//   [16..17] Command
//   [18..19] CreditRequest
//   [20..23] Flags
//   [24..27] NextCommand
//   [28..35] MessageId (incrémenté à chaque trame)
//   [36..39] Reserved / AsyncId
//   [40..43] TreeId
//   [44..51] SessionId
//   [52..67] Signature (HMAC-SHA256 tronqué à 16 o si signing actif)
inline void SMB_Session::_hdr(uint16_t command, uint16_t credit_charge) {
  _tx_len = 4;
  _tx[0]=0; _tx[1]=0; _tx[2]=0; _tx[3]=0;
  _tx[4]=0xFE; _tx[5]='S'; _tx[6]='M'; _tx[7]='B';
  size_t p=8;
  _put16(p,64);
  _put16(p,credit_charge);
  _put32(p,0);
  _put16(p,command);
  _put16(p,1);
  _put32(p,0);
  _put32(p,0);
  _put64(p,_message_id++);
  _put32(p,0);
  _put32(p,_tree_id);
  _put64(p,_session_id);
  for(int i=0;i<16;i++) _put8(p,0);
  _tx_len = p;
}

// Envoie _tx (préfixe NetBIOS compris) et lit la réponse complète dans _rx.
// Renseigne `status` (NT_Status), `resp_cmd` (commande SMB2) et met à jour
// _session_id / _credits. Retourne false si aucune réponse exploitable (timeout).
// ⚠️ Les offsets de lecture (_get32(12), _get16(16)…) comptent le préfixe
//    NetBIOS de 4 o : l'en-tête SMB2 commence donc à _rx[4].
inline bool SMB_Session::_sendRecv(uint32_t& status, uint16_t& resp_cmd) {
  if(_signing_active){
    _tx[4+16] |= 0x08;
    for(int i=0;i<16;i++) _tx[4+48+i]=0;
    uint8_t sig[32];
    SMBcrypto::hmacSha256(_session_key,16,&_tx[4],_tx_len-4,sig);
    memcpy(&_tx[4+48],sig,16);
  }
  uint32_t smb_len = _tx_len - 4;
  _tx[0]=0x00; _tx[1]=(smb_len>>16)&0xFF; _tx[2]=(smb_len>>8)&0xFF; _tx[3]=smb_len&0xFF;
  _client.write(_tx,_tx_len);
  _bytes_sent += _tx_len;
  _rx_len=0;
  uint32_t io_to = _io_timeout_ms ? _io_timeout_ms : 10000;
  unsigned long to = millis()+io_to;
  while(millis()<to){
    while(_client.available() && _rx_len<SMB_MAX_PAYLOAD) _rx[_rx_len++]=(uint8_t)_client.read();
    if(_rx_len>=4){
      uint32_t len=((uint32_t)_rx[1]<<16)|((uint32_t)_rx[2]<<8)|_rx[3];
      if(_rx_len>=len+4) break;
    }
    if(_feed_cb) _feed_cb();   // nourrit WDT/superviseur pendant l'attente
    delay(1);
  }
  _bytes_received += _rx_len;
  if(_rx_len<68){ status=0xFFFFFFFF; resp_cmd=0xFFFF; return false; }

  if(_signing_active && (_rx[4+16]&0x08)){
    uint32_t mlen=((uint32_t)_rx[1]<<16)|((uint32_t)_rx[2]<<8)|_rx[3];
    if(4+mlen<=_rx_len){
      uint8_t saved[16]; memcpy(saved,&_rx[4+48],16);
      memset(&_rx[4+48],0,16);
      uint8_t sig[32]; SMBcrypto::hmacSha256(_session_key,16,&_rx[4],mlen,sig);
      memcpy(&_rx[4+48],saved,16);
      if(memcmp(sig,saved,16)!=0) _last_error="Signature SMB2 réponse invalide";
    }
  }

  status=_get32(12); resp_cmd=_get16(16);
  uint16_t credits=_get16(18);
  if(credits) _credits=credits;
  _session_id=_get64(44);
  return true;
}

// ------------------------------ NEGOTIATE ------------------------------
inline bool SMB_Session::_negotiate() {
  _hdr(SMB2_NEGOTIATE);
  size_t p=_tx_len;
  _put16(p,36);
  _put16(p,2);
  _put16(p,1);
  _put16(p,0);
  _put32(p,0);
  for(int i=0;i<16;i++) _put8(p,0);
  _put32(p,0);
  _put16(p,0);
  _put16(p,0);
  _put16(p,0x0210);
  _put16(p,0x0202);
  _tx_len=p;

  uint32_t st; uint16_t cmd;
  if(!_sendRecv(st,cmd) || cmd!=SMB2_NEGOTIATE){
    char hex[48]; int n=0;
    for(size_t i=0;i<12 && i<_rx_len;i++) n+=snprintf(hex+n,sizeof(hex)-n,"%02X ", _rx[i]);
    _last_error="Négociation: réponse invalide (rx="+String((unsigned)_rx_len)+
                " conn="+String((int)_client.connected())+
                " cmd=0x"+String(cmd,HEX)+" st=0x"+String(st,HEX)+
                " ["+String(hex)+"])";
    return false;
  }
  if(st!=SMB2_STATUS_SUCCESS){ _last_error="Négociation échouée 0x"+String(st,HEX); return false; }
  _dialect=_get16(72);
  uint16_t secMode=_get16(70);
  _server_signing = (secMode & 0x03) != 0;
  return true;
}

// ---------------------------- SESSION_SETUP ----------------------------
inline bool SMB_Session::_sessionSetup() {
  uint8_t t1[64]; size_t t1l=0;
  const char* magic="NTLMSSP\0";
  memcpy(t1+t1l,magic,8); t1l+=8;
  auto put32=[&](uint8_t* b,size_t& o,uint32_t v){ b[o++]=v&0xFF;b[o++]=(v>>8)&0xFF;b[o++]=(v>>16)&0xFF;b[o++]=(v>>24)&0xFF; };
  auto put16=[&](uint8_t* b,size_t& o,uint16_t v){ b[o++]=v&0xFF;b[o++]=(v>>8)&0xFF; };
  put32(t1,t1l,1);
  put32(t1,t1l,0xA2088207);
  put16(t1,t1l,0); put16(t1,t1l,0); put32(t1,t1l,0);
  put16(t1,t1l,0); put16(t1,t1l,0); put32(t1,t1l,0);
  for(int i=0;i<8;i++) t1[t1l++]=0;

  uint8_t oidMech[]={0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a};
  uint8_t seq1[32]; size_t s1=0; s1=smbDerPut(seq1,s1,0x30,sizeof(oidMech)); memcpy(seq1+s1,oidMech,sizeof(oidMech)); s1+=sizeof(oidMech);
  uint8_t mech[64]; size_t mp=0; mp=smbDerPut(mech,mp,0xa0,s1); memcpy(mech+mp,seq1,s1); mp+=s1;
  uint8_t mt[128]; size_t mtp=0; mtp=smbDerPut(mt,mtp,0x04,t1l); memcpy(mt+mtp,t1,t1l); mtp+=t1l;
  uint8_t mt2[160]; size_t mt2p=0; mt2p=smbDerPut(mt2,mt2p,0xa2,mtp); memcpy(mt2+mt2p,mt,mtp); mt2p+=mtp;
  uint8_t seq[256]; size_t sp=0; sp=smbDerPut(seq,sp,0x30,mp+mt2p); memcpy(seq+sp,mech,mp); sp+=mp; memcpy(seq+sp,mt2,mt2p); sp+=mt2p;
  uint8_t wrap[256]; size_t wp=0; wp=smbDerPut(wrap,wp,0xa0,sp); memcpy(wrap+wp,seq,sp); wp+=sp;
  uint8_t oidSpnego[]={0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02};
  uint8_t spnego[512]; size_t sgl=0;
  sgl=smbDerPut(spnego,sgl,0x60,sizeof(oidSpnego)+wp);
  memcpy(spnego+sgl,oidSpnego,sizeof(oidSpnego)); sgl+=sizeof(oidSpnego);
  memcpy(spnego+sgl,wrap,wp); sgl+=wp;

  _hdr(SMB2_SESSION_SETUP);
  size_t p=_tx_len;
  _put16(p,25);
  _put8(p,0);
  _put8(p,1);
  _put32(p,0);
  _put32(p,0);
  _put16(p,64+24);
  _put16(p,(uint16_t)sgl);
  _put64(p,0);
  _putBytes(p,spnego,sgl);
  _tx_len=p;

  uint32_t st; uint16_t cmd;
  if(!_sendRecv(st,cmd) || cmd!=SMB2_SESSION_SETUP){ _last_error="Session setup: réponse invalide"; return false; }
  if(st!=SMB2_STATUS_MORE_PROCESSING && st!=SMB2_STATUS_SUCCESS){
    _last_error="Session setup échoué 0x"+String(st,HEX); return false;
  }
  if(st==SMB2_STATUS_SUCCESS){ _last_error="Session OK sans NTLM (guest)"; return true; }

  size_t secOff=_get16(72);
  size_t secLen=_get16(74);
  if(secOff+secLen>_rx_len){ _last_error="Blob SPNEGO tronqué"; return false; }
  int ntlmPos=-1;
  for(size_t i=secOff;i+8<secOff+secLen;i++){ if(memcmp(&_rx[i],"NTLMSSP\0",8)==0){ ntlmPos=(int)i; break; } }
  if(ntlmPos<0){ _last_error="NTLMSSP Type2 absent"; return false; }
  const uint8_t* t2=&_rx[ntlmPos];
  uint8_t challenge[8]; memcpy(challenge,t2+24,8);
  uint16_t tiLen=0, tiOff=0;
  if(secLen>=(size_t)(ntlmPos-secOff)+48){
    tiLen = t2[40] | (t2[41]<<8);
    tiOff = t2[44] | (t2[45]<<8) | (t2[46]<<16) | (t2[47]<<24);
  }
  if (tiLen > 400) tiLen = 400;
  const uint8_t* targetInfo = (tiLen && (size_t)(ntlmPos+(int)tiOff+tiLen)<=_rx_len) ? &_rx[ntlmPos+tiOff] : nullptr;
  if(!targetInfo) tiLen=0;

  uint8_t ntH[16]; SMBcrypto::ntHash(_config.password,ntH);
  uint8_t v2H[16]; SMBcrypto::ntlmv2Hash(ntH,_config.username,_config.workgroup,v2H);

  uint8_t clientChal[8];
  for(int i=0;i<8;i++) clientChal[i]=(uint8_t)(random(256) & 0xFF);

  uint8_t blob[512]; size_t bl=0;
  blob[bl++]=0x01; blob[bl++]=0x01; blob[bl++]=0x00; blob[bl++]=0x00;
  blob[bl++]=0x00; blob[bl++]=0x00; blob[bl++]=0x00; blob[bl++]=0x00;
  uint64_t ft=((uint64_t)time(nullptr)+11644473600ULL)*10000000ULL;
  for(int i=0;i<8;i++) blob[bl++]=(uint8_t)(ft>>(8*i));
  memcpy(blob+bl,clientChal,8); bl+=8;
  blob[bl++]=0x00; blob[bl++]=0x00; blob[bl++]=0x00; blob[bl++]=0x00;
  if(targetInfo){ memcpy(blob+bl,targetInfo,tiLen); bl+=tiLen; }
  blob[bl++]=0x00; blob[bl++]=0x00; blob[bl++]=0x00; blob[bl++]=0x00;

  uint8_t proofIn[8+512]; memcpy(proofIn,challenge,8); memcpy(proofIn+8,blob,bl);
  uint8_t ntProof[16]; SMBcrypto::hmacMd5(v2H,16,proofIn,8+bl,ntProof);

  uint8_t ntResp[16+512]; memcpy(ntResp,ntProof,16); memcpy(ntResp+16,blob,bl);
  size_t ntRespLen=16+bl;

  uint8_t lmIn[8+8]; memcpy(lmIn,challenge,8); memcpy(lmIn+8,clientChal,8);
  uint8_t lmProof[16]; SMBcrypto::hmacMd5(v2H,16,lmIn,16,lmProof);
  uint8_t lmResp[24]; memcpy(lmResp,lmProof,16); memcpy(lmResp+16,clientChal,8);

  uint8_t domU[128]; size_t domLen; SMBcrypto::toUTF16LE(_config.workgroup,domU,domLen);
  uint8_t usrU[128]; size_t usrLen; SMBcrypto::toUTF16LE(_config.username,usrU,usrLen);
  uint8_t wksU[128]; size_t wksLen; SMBcrypto::toUTF16LE("ESP8266",wksU,wksLen);

  uint8_t t3[1024]; size_t t3l=0;
  memcpy(t3+t3l,magic,8); t3l+=8;
  put32(t3,t3l,3);
  size_t off=88;
  put16(t3,t3l,(uint16_t)24); put16(t3,t3l,(uint16_t)24); put32(t3,t3l,(uint32_t)off);
  put16(t3,t3l,(uint16_t)ntRespLen); put16(t3,t3l,(uint16_t)ntRespLen); put32(t3,t3l,(uint32_t)(off+24));
  put16(t3,t3l,(uint16_t)domLen); put16(t3,t3l,(uint16_t)domLen); put32(t3,t3l,(uint32_t)(off+24+ntRespLen));
  put16(t3,t3l,(uint16_t)usrLen); put16(t3,t3l,(uint16_t)usrLen); put32(t3,t3l,(uint32_t)(off+24+ntRespLen+domLen));
  put16(t3,t3l,(uint16_t)wksLen); put16(t3,t3l,(uint16_t)wksLen); put32(t3,t3l,(uint32_t)(off+24+ntRespLen+domLen+usrLen));
  put16(t3,t3l,0); put16(t3,t3l,0); put32(t3,t3l,0);
  put32(t3,t3l,0xA2888207);
  { const uint8_t ver[8]={0x06,0x01,0xB1,0x1D,0x00,0x00,0x00,0x0F}; memcpy(t3+t3l,ver,8); t3l+=8; }
  for(int i=0;i<16;i++) t3[t3l++]=0;
  memcpy(t3+t3l,lmResp,24); t3l+=24;
  memcpy(t3+t3l,ntResp,ntRespLen); t3l+=ntRespLen;
  memcpy(t3+t3l,domU,domLen); t3l+=domLen;
  memcpy(t3+t3l,usrU,usrLen); t3l+=usrLen;
  memcpy(t3+t3l,wksU,wksLen); t3l+=wksLen;

  SMBcrypto::hmacMd5(v2H,16,ntProof,16,_session_key);

  {
    uint16_t tnLen  = (uint16_t)(t2[12] | (t2[13]<<8));
    uint32_t tnOff  = (uint32_t)t2[16] | ((uint32_t)t2[17]<<8) | ((uint32_t)t2[18]<<16) | ((uint32_t)t2[19]<<24);
    uint16_t tiL2   = (uint16_t)(t2[40] | (t2[41]<<8));
    uint32_t tiO2   = (uint32_t)t2[44] | ((uint32_t)t2[45]<<8) | ((uint32_t)t2[46]<<16) | ((uint32_t)t2[47]<<24);
    uint32_t t2flags= (uint32_t)t2[20] | ((uint32_t)t2[21]<<8) | ((uint32_t)t2[22]<<16) | ((uint32_t)t2[23]<<24);
    uint32_t t2len  = 48 + ((t2flags & 0x02000000) ? 8 : 0);
    if (tnOff + tnLen > t2len) t2len = tnOff + tnLen;
    if (tiO2 + tiL2 > t2len)  t2len = tiO2 + tiL2;
    uint32_t avail = (uint32_t)((secOff + secLen) - ntlmPos);
    if (t2len > avail) t2len = avail;

    uint8_t micIn[1024]; size_t mlen=0;
    memcpy(micIn+mlen, t1, t1l); mlen+=t1l;
    memcpy(micIn+mlen, t2, t2len); mlen+=t2len;
    memcpy(micIn+mlen, t3, t3l); mlen+=t3l;
    uint8_t mic[16];
    SMBcrypto::hmacMd5(_session_key,16,micIn,mlen,mic);
    memcpy(t3+72,mic,16);
  }

  uint8_t rTok[1024]; size_t rp=0;
  rp=smbDerPut(rTok,rp,0x04,t3l); memcpy(rTok+rp,t3,t3l); rp+=t3l;
  uint8_t rW[1100]; size_t rw=0;
  rw=smbDerPut(rW,rw,0xa2,rp); memcpy(rW+rw,rTok,rp); rw+=rp;
  uint8_t rSeq[1100]; size_t rs=0;
  rs=smbDerPut(rSeq,rs,0x30,rw); memcpy(rSeq+rs,rW,rw); rs+=rw;
  uint8_t rOut[1150]; size_t ro=0;
  ro=smbDerPut(rOut,ro,0xa1,rs); memcpy(rOut+ro,rSeq,rs); ro+=rs;

  _hdr(SMB2_SESSION_SETUP);
  p=_tx_len;
  _put16(p,25);
  _put8(p,0);
  _put8(p,1);
  _put32(p,0);
  _put32(p,0);
  _put16(p,64+24);
  _put16(p,(uint16_t)ro);
  _put64(p,0);
  _putBytes(p,rOut,ro);
  _tx_len=p;

  if(!_sendRecv(st,cmd) || cmd!=SMB2_SESSION_SETUP){ _last_error="Auth: réponse invalide"; return false; }
  if(st!=SMB2_STATUS_SUCCESS){ _last_error="Authentification échouée 0x"+String(st,HEX); return false; }

  _signing_active = _server_signing;
  return true;
}

// ---------------------------- TREE_CONNECT ----------------------------
inline String SMB_Session::_unc() const {
  return String("\\\\") + String(_config.host) + "\\" + String(_config.share);
}

inline bool SMB_Session::_treeConnect() {
  _hdr(SMB2_TREE_CONNECT);
  size_t p=_tx_len;
  _put16(p,9);
  _put16(p,0);
  _put16(p,64+8);
  String unc=_unc();
  uint16_t plen=(uint16_t)(unc.length()*2);
  _put16(p,plen);
  for(size_t i=0;i<unc.length();i++){ _put8(p,(uint8_t)unc[i]); _put8(p,0); }
  _tx_len=p;

  uint32_t st; uint16_t cmd;
  if(!_sendRecv(st,cmd) || cmd!=SMB2_TREE_CONNECT){ _last_error="Tree connect: réponse invalide"; return false; }
  if(st!=SMB2_STATUS_SUCCESS){ _last_error="Tree connect échoué 0x"+String(st,HEX); return false; }
  _tree_id=_get32(40);
  return true;
}

// ------------------------------- CREATE -------------------------------
// CREATE SMB2 : ouvre/crée un fichier (ou un dossier si `directory`).
// En sortie, le FileId renvoyé est mémorisé dans _file_id et la taille dans
// _file_size (offsets de la réponse CREATE : FileId à _rx[132], EndOfFile à
// _rx[116] — toujours décalés du préfixe NetBIOS de 4 o).
inline bool SMB_Session::_create(const char* path, uint32_t desired_access,
                                 uint32_t create_disp, uint32_t create_options, bool directory) {
  _hdr(SMB2_CREATE);
  size_t p=_tx_len;
  _put16(p,57);
  _put8(p,0);
  _put8(p,0);
  _put32(p,2);
  _put64(p,0);
  _put64(p,0);
  _put32(p,desired_access);
  _put32(p,directory?0x10:0x80);
  _put32(p,0x07);
  _put32(p,create_disp);
  _put32(p,create_options);
  String sp=_path(path);
  uint16_t nlen=(uint16_t)(sp.length()*2);
  _put16(p,64+56);
  _put16(p,nlen);
  _put32(p,0);
  _put32(p,0);
  for(size_t i=0;i<sp.length();i++){ _put8(p,(uint8_t)sp[i]); _put8(p,0); }
  _tx_len=p;

  uint32_t st; uint16_t cmd;
  if(!_sendRecv(st,cmd) || cmd!=SMB2_CREATE){ _last_error="Create: réponse invalide"; return false; }
  if(st!=SMB2_STATUS_SUCCESS && st!=SMB2_STATUS_OBJECT_NAME_COLLISION){
    _last_error="Create '"+sp+"' échoué 0x"+String(st,HEX); return false;
  }
  memcpy(_file_id,&_rx[132],16);
  _file_size=_get64(116);
  return true;
}

inline bool SMB_Session::_close() {
  if(!_connected && _tree_id==0) return true;
  _hdr(SMB2_CLOSE);
  size_t p=_tx_len;
  _put16(p,24); _put16(p,0); _put32(p,0);
  for(int i=0;i<16;i++) _put8(p,_file_id[i]);
  _tx_len=p;
  uint32_t st; uint16_t cmd;
  _sendRecv(st,cmd);
  memset(_file_id,0,16);
  _file_size=0;
  return true;
}

inline bool SMB_Session::_write(const uint8_t* data, size_t len, uint64_t offset) {
  // ⚠️ Découpage obligatoire : un seul paquet dépasserait _tx[SMB_MAX_PAYLOAD]
  // (aucun contrôle de borne dans l'assemblage). On écrit par morceaux.
  const size_t CHUNK = 3072;
  size_t done = 0;
  do {
    size_t n = len - done;
    if (n > CHUNK) n = CHUNK;
    _hdr(SMB2_WRITE);
    size_t p=_tx_len;
    _put16(p,49);
    _put16(p,64+48);
    _put32(p,(uint32_t)n);
    _put64(p,offset+done);
    for(int i=0;i<16;i++) _put8(p,_file_id[i]);
    _put32(p,0);
    _put32(p,0);
    _put16(p,0);
    _put16(p,0);
    _put32(p,0);
    _putBytes(p,data+done,n);
    _tx_len=p;
    uint32_t st; uint16_t cmd;
    if(!_sendRecv(st,cmd) || cmd!=SMB2_WRITE){ _last_error="Write: réponse invalide"; return false; }
    if(st!=SMB2_STATUS_SUCCESS){ _last_error="Write échoué 0x"+String(st,HEX); return false; }
    done += n;
  } while (done < len);
  return true;
}

// ------------------------------- READ / WRITE -------------------------------
// Lecture à `offset` : les données utiles commencent à _rx[4 + DataOffset]
// (DataOffset en _rx[70], longueur en _rx[72]).
inline bool SMB_Session::_read(uint8_t* buffer, size_t max_len, uint64_t offset, size_t& bytes_read) {
  bytes_read=0;
  _hdr(SMB2_READ);
  size_t p=_tx_len;
  _put16(p,49);
  _put8(p,0);
  _put8(p,0);
  _put32(p,(uint32_t)max_len);
  _put64(p,offset);
  for(int i=0;i<16;i++) _put8(p,_file_id[i]);
  _put32(p,0);
  _put32(p,0);
  _put32(p,0);
  _put16(p,0);
  _put16(p,0);
  _put8(p,0);
  _tx_len=p;
  uint32_t st; uint16_t cmd;
  if(!_sendRecv(st,cmd) || cmd!=SMB2_READ){ _last_error="Read: réponse invalide"; return false; }
  if(st==SMB2_STATUS_END_OF_FILE){ return true; }
  if(st!=SMB2_STATUS_SUCCESS){ _last_error="Read échoué 0x"+String(st,HEX); return false; }
  uint8_t dataOff=_rx[70];
  uint32_t dataLen=_get32(72);
  if(dataLen>max_len) dataLen=max_len;
  if(4+dataOff+dataLen>_rx_len) dataLen=_rx_len-(4+dataOff);
  memcpy(buffer,&_rx[4+dataOff],dataLen);
  bytes_read=dataLen;
  return true;
}

inline bool SMB_Session::_setDelete() {
  _hdr(SMB2_SET_INFO);
  size_t p=_tx_len;
  _put16(p,33);
  _put8(p,1);
  _put8(p,0x0D);
  _put32(p,1);
  _put32(p,0);
  _put32(p,0);
  for(int i=0;i<16;i++) _put8(p,_file_id[i]);
  _put8(p,1);
  _tx_len=p;
  uint32_t st; uint16_t cmd;
  if(!_sendRecv(st,cmd)){ _last_error="SetInfo: réponse invalide"; return false; }
  if(st!=SMB2_STATUS_SUCCESS){ _last_error="Delete échoué 0x"+String(st,HEX); return false; }
  return true;
}

// ---------------------------- QUERY_DIRECTORY ----------------------------
// Parcourt un dossier via FILE_ID_BOTH_DIR_INFORMATION. Chaque entrée commence
// à `off` et occupe `NextEntryOffset` octets :
//   [off+0]  NextEntryOffset (0 = dernière entrée)
//   [off+40] EndOfFile (taille)
//   [off+56] FileAttributes (bit 0x10 = dossier)
//   [off+60] FileNameLength (octets, UTF-16LE)
//   [off+102] FileName (UTF-16LE)
// Les entrées "." et ".." sont filtrées avant l'appel du callback.
inline bool SMB_Session::_queryDir(const char* path, SMB_ListCallback callback) {
  if(!_create(path,0x00000001,0x01,0x00000001,true)) return false;
  _hdr(SMB2_QUERY_DIRECTORY);
  size_t p=_tx_len;
  _put16(p,33);
  _put8(p,0x25);
  _put8(p,0x00);
  _put32(p,0);
  for(int i=0;i<16;i++) _put8(p,_file_id[i]);
  _put16(p,0);
  _put16(p,0);
  _put32(p,2048);
  _put8(p,0);
  _tx_len=p;
  uint32_t st; uint16_t cmd;
  if(!_sendRecv(st,cmd) || cmd!=SMB2_QUERY_DIRECTORY){ _last_error="QueryDir: réponse invalide"; _close(); return false; }
  if(st!=SMB2_STATUS_NO_MORE_FILES && st!=SMB2_STATUS_SUCCESS){ _last_error="QueryDir 0x"+String(st,HEX); _close(); return false; }
  if(st==SMB2_STATUS_SUCCESS){
    uint16_t outLen=_get32(72);
    uint16_t outOff=_get16(70);
    size_t off=4+outOff;
    size_t end=4+outOff+outLen;
    while(off+102<=end && off+102<=_rx_len){
      uint32_t next=_get32(off);
      uint32_t nameLen=_get32(off+60);
      uint8_t attrs=_rx[off+56];
      size_t nameOff=off+102;
      if(nameLen>200) nameLen=200;
      SMB_FileInfo info; memset(&info,0,sizeof(info));
      size_t cp=nameLen/2; if(cp>120) cp=120;
      for(size_t i=0;i<cp;i++) info.name[i]=(char)_rx[nameOff+i*2];
      info.name[cp]='\0';
      info.is_directory=(attrs&0x10)!=0;
      info.size=_get64(off+40);
      if(callback && info.name[0] && strcmp(info.name,".") && strcmp(info.name,"..")) callback(info);
      if(next==0) break;
      off+=next;
    }
  }
  _close();
  return true;
}

// ============================================================================
// API PUBLIQUE — chemins et helpers de mode
// ============================================================================
inline String SMB_Session::_path(const char* rel) const {
  String p;
  if(rel && rel[0]){ if(rel[0]=='/') rel++; p=rel; }
  p.replace("/","\\");
  return p;
}

inline uint32_t SMB_Session::_modeAccess(SMB_OpenMode m) const {
  switch(m){
    case SMB_READ: return 0x00000001;                 // READ
    default:       return 0x0012019F;                 // READ|WRITE|APPEND|...
  }
}
inline uint32_t SMB_Session::_modeDisposition(SMB_OpenMode m) const {
  switch(m){
    case SMB_READ:          return 0x01;  // FILE_OPEN
    case SMB_CREATE:        return 0x02;  // FILE_CREATE
    case SMB_CREATE_ALWAYS: return 0x05;  // FILE_OVERWRITE_IF
    case SMB_OPEN_ALWAYS:   return 0x03;  // FILE_OPEN_IF
    case SMB_APPEND:
    case SMB_WRITE:
    default:                return 0x03;  // FILE_OPEN_IF
  }
}

// ============================================================================
// SMB_File
// ============================================================================
inline bool SMB_File::open(SMB_Session* s, const char* path, SMB_OpenMode mode) {
  if(!s) return false;
  _s = s;
  s->lock();
  bool ok = s->_create(path, s->_modeAccess(mode), s->_modeDisposition(mode), 0x00000040, false);
  if(ok){
    memcpy(_file_id, s->_file_id, 16);
    _size = s->_file_size;
    _pos = (mode == SMB_APPEND) ? _size : 0;
    strlcpy(_path, path, sizeof(_path));
    _open = true;
  }
  s->unlock();
  return ok;
}

inline void SMB_File::close() {
  if(!_s || !_open) return;
  _s->lock();
  memcpy(_s->_file_id, _file_id, 16);
  _s->_close();
  _s->unlock();
  _open = false;
  memset(_file_id, 0, 16);
}

inline bool SMB_File::remove() {
  if(!_s) return false;
  _s->lock();
  bool ok = _s->remove(_path);
  _s->unlock();
  if(ok) _open = false;
  return ok;
}

inline int SMB_File::read(uint8_t* buf, size_t len) {
  if(!_s || !_open) return -1;
  _s->lock();
  memcpy(_s->_file_id, _file_id, 16);
  size_t got=0;
  bool ok = _s->_read(buf, len, _pos, got);
  _s->unlock();
  if(!ok) return -1;
  _pos += got;
  return (int)got;
}

inline int SMB_File::write(const uint8_t* buf, size_t len) {
  if(!_s || !_open) return -1;
  _s->lock();
  memcpy(_s->_file_id, _file_id, 16);
  bool ok = _s->_write(buf, len, _pos);
  _s->unlock();
  if(!ok) return -1;
  _pos += len;
  if(_pos > _size) _size = _pos;
  return (int)len;
}

inline int SMB_File::append(const uint8_t* buf, size_t len) {
  if(!_s || !_open) return -1;
  _s->lock();
  memcpy(_s->_file_id, _file_id, 16);
  bool ok = _s->_write(buf, len, _size);
  _s->unlock();
  if(!ok) return -1;
  _size += len;
  _pos = _size;
  return (int)len;
}

inline bool SMB_File::seek(uint64_t pos) {
  if(!_s || !_open) return false;
  _pos = pos;
  return true;
}

// ============================================================================
// SMB_Session — opérations sync
// ============================================================================
inline bool SMB_Session::open(SMB_File& f, const char* path, SMB_OpenMode mode) {
  return f.open(this, path, mode);
}

inline bool SMB_Session::remove(const char* path) {
  if(!_connected){ _last_error="Non connecté"; return false; }
  if(!_create(path,0x00010000,0x01,0x00000040,false)) return false;
  bool ok=_setDelete();
  _close();
  if(!ok) _errors++;
  return ok;
}

inline bool SMB_Session::exists(const char* path) {
  if(!_connected) return false;
  String save=_last_error;
  bool ok=_create(path,0x00000001,0x01,0x00000040,false);
  if(ok) _close();
  else   _last_error=save;
  return ok;
}

inline bool SMB_Session::mkdir(const char* path) {
  if(!_connected){ _last_error="Non connecté"; return false; }
  if(_create(path,0x00100000|0x00000001|0x00000080,0x03,0x00000001,true)){ _close(); return true; }
  if(_last_error.indexOf("0xC0000035")>=0) return true; // existe déjà
  return false;
}

inline bool SMB_Session::listDir(const char* path, SMB_ListCallback callback) {
  if(!_connected){ _last_error="Non connecté"; return false; }
  return _queryDir(path, callback);
}

inline bool SMB_Session::readAll(const char* path, SMB_LineCallback cb, size_t maxBytes) {
  if(!_connected){ _last_error="Non connecté"; return false; }
  if(!_create(path,0x00000001,0x01,0x00000040,false)) return false;
  uint64_t offset=0; String partial=""; bool first=true; uint8_t chunk[1024];
  size_t total=0;
  while(true){
    size_t got=0;
    // ⚠️ Distinguer la fin de fichier (got==0) d'une ERREUR de lecture
    // (ex. STATUS_PENDING 0x103) : sinon une lecture TRONQUÉE était signalée
    // comme réussie (retour true) → anneau du jour partiel sans réessai.
    if(!_read(chunk,sizeof(chunk),offset,got)){ _close(); return false; }
    if(got==0) break;
    offset+=got; total+=got;
    for(size_t i=0;i<got;i++){
      char c=(char)chunk[i];
      if(c=='\n'){
        partial.trim();
        if(partial.length()>0 && cb) cb(partial.c_str(),first);
        partial=""; first=false;
      } else if(c!='\r') partial+=c;
    }
    if(maxBytes && total>=maxBytes) break;
  }
  _close();
  return true;
}

inline bool SMB_Session::readTail(const char* path, SMB_LineCallback cb, size_t maxBytes) {
  if(!_connected){ _last_error="Non connecté"; return false; }
  if(!_create(path,0x00000001,0x01,0x00000040,false)) return false;
  uint64_t size=_file_size;
  if(size==0){ _last_error="Fichier vide"; _close(); return false; }
  static uint8_t buf[4096];
  size_t chunk = maxBytes; if(chunk>sizeof(buf)) chunk=sizeof(buf);
  bool whole = (size<=chunk);
  if(chunk>(size_t)size) chunk=(size_t)size;
  size_t got=0;
  if(!_read(buf,chunk,size-chunk,got) || got==0){ _last_error="Read tail échoué (size="+String((unsigned)size)+")"; _close(); return false; }
  String partial=""; bool firstLine=true;
  for(size_t i=0;i<got;i++){
    char c=(char)buf[i];
    if(c=='\n'){
      partial.trim();
      if(partial.length()>0){
        if(firstLine && !whole){ /* ligne partielle : ignorée */ }
        else if(cb) cb(partial.c_str(), firstLine && whole);
      }
      partial=""; firstLine=false;
    } else if(c!='\r') partial+=c;
  }
  _close();
  return true;
}

inline bool SMB_Session::readLastLine(const char* path, char* buffer, size_t buflen) {
  if(!_connected){ _last_error="Non connecté"; return false; }
  if(!_create(path,0x00000001,0x01,0x00000040,false)) return false;
  uint64_t size=_file_size;
  if(size==0){ _close(); return false; }
  size_t chunk_size=512; if(chunk_size>size) chunk_size=(size_t)size;
  uint8_t chunk[512]; size_t got=0;
  if(!_read(chunk,chunk_size,size-chunk_size,got) || got==0){ _close(); return false; }
  int end=(int)got-1;
  while(end>=0 && (chunk[end]=='\n'||chunk[end]=='\r')) end--;
  int start=end;
  while(start>=0 && chunk[start]!='\n') start--;
  start++;
  size_t len=end-start+1;
  if(len>=buflen) len=buflen-1;
  memcpy(buffer,&chunk[start],len); buffer[len]='\0';
  _close();
  return len>0;
}

inline bool SMB_Session::writeFile(const char* path, const String& content) {
  if(!_connected){ _last_error="Non connecté"; return false; }
  if(!_create(path,0x0012019F,0x05,0x00000040,false)) return false;
  bool ok = _write((const uint8_t*)content.c_str(), content.length(), 0);
  _close();
  if(!ok) _errors++;
  return ok;
}

inline bool SMB_Session::append(const char* path, const String& content) {
  if(!_connected){ _last_error="Non connecté"; return false; }
  if(!_create(path,0x0012019F,0x03,0x00000040,false)) return false;
  bool ok=_write((const uint8_t*)content.c_str(), content.length(), _file_size);
  _close();
  if(!ok) _errors++;
  return ok;
}

inline bool SMB_Session::_logoff() {
  _hdr(SMB2_LOGOFF);
  size_t p=_tx_len; _put16(p,4); _tx_len=p;
  uint32_t st; uint16_t cmd; _sendRecv(st,cmd);
  _session_id=0; _tree_id=0;
  return true;
}

inline bool SMB_Session::syncTime(const char* ntp_server, int timezone_offset) {
  configTime(timezone_offset,0,ntp_server);
  _last_error="NTP sync démarré";
  unsigned long t=millis()+10000;
  while(time(nullptr)<100000 && millis()<t) delay(100);
  return time(nullptr)>100000;
}

// ============================================================================
// SMB_Session — file d'attente non bloquante (async)
// ============================================================================
inline int SMB_Session::submit(const SMB_Request& req) {
  _ensureInit();
  if(!_queue) return -1;
  lock();
  int id=-1;
  for(int i=0;i<SMB_REQ_SLOTS;i++){ if(!_slotUsed[i]){ id=i; break; } }
  if(id<0){ unlock(); return -1; }
  _slotUsed[id]=true;
  _slots[id]=req;
  _slots[id].status=SMB_PENDING;
  _slots[id].result=false;
  _slots[id].error="";
  unlock();
  int8_t idx=(int8_t)id;
  if(xQueueSend(_queue,&idx,0)!=pdTRUE){ lock(); _slotUsed[id]=false; unlock(); return -1; }
  return id;
}

inline SMB_Status SMB_Session::status(int id) const {
  if(id<0 || id>=SMB_REQ_SLOTS) return SMB_ERROR;
  return _slots[id].status;
}
inline bool SMB_Session::result(int id) const {
  if(id<0 || id>=SMB_REQ_SLOTS) return false;
  return _slots[id].result;
}
inline String SMB_Session::error(int id) const {
  if(id<0 || id>=SMB_REQ_SLOTS) return String("id invalide");
  return _slots[id].error;
}
inline void SMB_Session::release(int id) {
  if(id<0 || id>=SMB_REQ_SLOTS) return;
  lock();
  _slotUsed[id]=false;
  _slots[id].status=SMB_IDLE;
  unlock();
}
inline int SMB_Session::pending() const {
  if(!_queue) return 0;
  return (int)uxQueueMessagesWaiting(_queue);
}

inline void SMB_Session::poll() {
  _ensureInit();
  if(!_queue) return;
  int8_t id;
  if(xQueueReceive(_queue,&id,0)!=pdTRUE) return;
  if(id<0 || id>=SMB_REQ_SLOTS) return;
  _slots[id].status=SMB_RUNNING;
  bool ok=false;
  switch(_slots[id].type){
    case SMB_REQ_CONNECT:    ok = begin(_config); break;
    case SMB_REQ_DISCONNECT: end(); ok=true; break;
    case SMB_REQ_REMOVE:     ok = remove(_slots[id].path); break;
    case SMB_REQ_EXISTS:     ok = exists(_slots[id].path); break;
    case SMB_REQ_MKDIR:      ok = mkdir(_slots[id].path); break;
    case SMB_REQ_LIST:       ok = listDir(_slots[id].path, nullptr); break;
    case SMB_REQ_READALL:    ok = readAll(_slots[id].path, nullptr, _slots[id].maxBytes); break;
    case SMB_REQ_READTAIL:   ok = readTail(_slots[id].path, nullptr, _slots[id].maxBytes); break;
    case SMB_REQ_WRITEFILE:  ok = writeFile(_slots[id].path, String(_slots[id].content ? _slots[id].content : "")); break;
    case SMB_REQ_APPEND:     ok = append(_slots[id].path, String(_slots[id].content ? _slots[id].content : "")); break;
    default: ok=false; break;
  }
  _slots[id].result=ok;
  _slots[id].status = ok ? SMB_DONE : SMB_ERROR;
  _slots[id].error = _last_error;
}

// ------------------------- Helpers transport -------------------------
inline void SMB_Session::_put8(size_t& p, uint8_t v){ _tx[p++]=v; }
inline void SMB_Session::_put16(size_t& p, uint16_t v){ _tx[p++]=v&0xFF; _tx[p++]=(v>>8)&0xFF; }
inline void SMB_Session::_put32(size_t& p, uint32_t v){ _tx[p++]=v&0xFF;_tx[p++]=(v>>8)&0xFF;_tx[p++]=(v>>16)&0xFF;_tx[p++]=(v>>24)&0xFF; }
inline void SMB_Session::_put64(size_t& p, uint64_t v){ for(int i=0;i<8;i++) _tx[p++]=(v>>(8*i))&0xFF; }
inline void SMB_Session::_putBytes(size_t& p, const void* d, size_t n){ memcpy(&_tx[p],d,n); p+=n; }
inline uint16_t SMB_Session::_get16(size_t p) const { return (uint16_t)(_rx[p]|(_rx[p+1]<<8)); }
inline uint32_t SMB_Session::_get32(size_t p) const { return (uint32_t)_rx[p]|((uint32_t)_rx[p+1]<<8)|((uint32_t)_rx[p+2]<<16)|((uint32_t)_rx[p+3]<<24); }
inline uint64_t SMB_Session::_get64(size_t p) const { uint64_t v=0; for(int i=0;i<8;i++) v|=((uint64_t)_rx[p+i])<<(8*i); return v; }

inline SMB_Config defaultSMBConfig() {
  SMB_Config cfg;
  memset(&cfg, 0, sizeof(cfg));
  strcpy(cfg.host,"host.local");
  strcpy(cfg.share,"hdd1");
  strcpy(cfg.path,"path");
  strcpy(cfg.username,"user");
  strcpy(cfg.password,"pass123");
  strcpy(cfg.workgroup,"WORKGROUP");
  cfg.port=SMB_PORT;
  cfg.use_encryption=false;
  return cfg;
}

#endif // SMB_FILE_H
