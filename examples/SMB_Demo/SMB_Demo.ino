/*
 * SMB_file - exemple SMB_Demo
 * https://github.com/Fo170/SMB_file
 *
 * Démontre l'usage de la librairie SMB_file (client SMB 2.1 / NTLMv2) :
 *   - connexion WiFi puis session SMB ;
 *   - API synchrone : mkdir, writeFile, append, exists, listDir, readAll,
 *     readTail, readLastLine et handle SMB_File (read/write/seek) ;
 *   - API asynchrone : submit() + poll() exécuté par une tâche FreeRTOS dédiée.
 *
 * Prérequis : ESP32, partage SMB 2.x (Samba : server min protocol = SMB2,
 * server signing = auto). Renseignez les identifiants ci-dessous.
 *
 * ⚠️ Les I/O SMB sont bloquantes : n'appelez jamais les méthodes sync depuis une
 *    tâche temps-réel ou le watchdog. Ici tout se fait dans setup().
 */

#include <Arduino.h>
#include <WiFi.h>
#include <SMB_file.h>

// ---------------------------------------------------------------------------
// À PERSONNALISER
// ---------------------------------------------------------------------------
static const char* WIFI_SSID = "VOTRE_SSID";
static const char* WIFI_PASS = "VOTRE_MOT_DE_PASSE";

static const char* SMB_HOST  = "192.168.1.209";  // ou "omv2.local"
static const char* SMB_SHARE = "hdd1";           // nom du partage
static const char* SMB_ROOT  = "ProductionSolaire"; // sous-dossier du partage
static const char* SMB_USER  = "user";
static const char* SMB_PASS  = "pass123";
static const char* SMB_DOMAIN = "WORKGROUP";

// ---------------------------------------------------------------------------
// Objets globaux
// ---------------------------------------------------------------------------
SMB_Session smb;

// Tampon statique utilisé par la requête asynchrone : il doit rester valide
// jusqu'à ce que le statut passe à SMB_DONE / SMB_ERROR.
static const char ASYNC_LINE[] = "ligne ajoutee en mode async\r\n";

// Callback de listing de répertoire
static void onDirEntry(const SMB_FileInfo& info) {
  Serial.printf("  %s%s (%lu o)\n", info.name,
                info.is_directory ? "/" : "", (unsigned long)info.size);
}

// Callback de lecture ligne par ligne
static void onLine(const char* line, bool is_header) {
  Serial.printf("  %s%s\n", is_header ? "[entete] " : "", line);
}

// Attend la fin d'une requête asynchrone (un autre contexte appelle poll()).
static bool waitAsync(int id, uint32_t timeout_ms) {
  uint32_t t0 = millis();
  while (millis() - t0 < timeout_ms) {
    SMB_Status st = smb.status(id);
    if (st == SMB_DONE)  return smb.result(id);
    if (st == SMB_ERROR) return false;
    delay(10);
  }
  return false;
}

// Tâche dédiée : exécute en boucle UNE requête asynchrone.
static void taskSMB(void* pv) {
  (void)pv;
  for (;;) {
    smb.poll();
    vTaskDelay(pdMS_TO_TICKS(50));
  }
}

// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n=== SMB_file : exemple SMB_Demo ===");

  // 1) WiFi -----------------------------------------------------------------
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connexion WiFi ");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf(" OK (%s)\n", WiFi.localIP().toString().c_str());

  // 2) Configuration SMB ----------------------------------------------------
  SMB_Config cfg = defaultSMBConfig();
  strlcpy(cfg.host,      SMB_HOST,   sizeof(cfg.host));
  strlcpy(cfg.share,     SMB_SHARE,  sizeof(cfg.share));
  strlcpy(cfg.path,      SMB_ROOT,   sizeof(cfg.path));
  strlcpy(cfg.username,  SMB_USER,   sizeof(cfg.username));
  strlcpy(cfg.password,  SMB_PASS,   sizeof(cfg.password));
  strlcpy(cfg.workgroup, SMB_DOMAIN, sizeof(cfg.workgroup));
  cfg.io_timeout_ms = 15000;   // timeout I/O par aller-retour (ms)

  // Callback appelé pendant les attentes réseau (nourrit le watchdog).
  smb.setFeedCallback([]() { /* esp_task_wdt_reset(); */ });

  // 3) Connexion SMB --------------------------------------------------------
  if (!smb.begin(cfg)) {
    Serial.printf("begin() a echoue : %s\n", smb.lastError().c_str());
    return;
  }
  Serial.printf("Connecte - dialecte 0x%04X\n", smb.dialect());

  // 4) Opérations synchrones ------------------------------------------------
  const char* csv = "logs/demo.csv";

  Serial.println("mkdir(logs) :");
  Serial.println(smb.mkdir("logs") ? "  OK" : "  ECHEC");

  Serial.println("writeFile(demo.csv) :");
  Serial.println(smb.writeFile(csv, "entete;valeur\r\n1;100\r\n")
                     ? "  OK" : "  ECHEC");

  Serial.println("append(demo.csv) :");
  Serial.println(smb.append(csv, "2;200\r\n") ? "  OK" : "  ECHEC");

  Serial.printf("exists(%s) : %s\n", csv, smb.exists(csv) ? "oui" : "non");

  Serial.println("listDir(logs) :");
  smb.listDir("logs", onDirEntry);

  Serial.println("readAll(demo.csv) :");
  smb.readAll(csv, onLine);

  Serial.println("readTail(demo.csv, 64) :");
  smb.readTail(csv, onLine, 64);

  char last[128] = {0};
  if (smb.readLastLine(csv, last, sizeof(last)))
    Serial.printf("readLastLine -> %s\n", last);

  // 5) Handle SMB_File (accès aléatoire) ------------------------------------
  SMB_File f;
  if (smb.open(f, "logs/binaire.bin", SMB_CREATE_ALWAYS)) {
    const uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    f.write(payload, sizeof(payload));
    f.seek(0);
    uint8_t rd[4] = {0};
    int n = f.read(rd, sizeof(rd));
    Serial.printf("SMB_File read -> %d octet(s)\n", n);
    f.close();
  } else {
    Serial.printf("open() binaire a echoue : %s\n", smb.lastError().c_str());
  }

  // 6) API asynchrone (non bloquante) ---------------------------------------
  xTaskCreatePinnedToCore(taskSMB, "Task_SMB", 8192, nullptr, 1, nullptr, 0);

  SMB_Request req = {};
  req.type = SMB_REQ_APPEND;
  strlcpy(req.path, csv, sizeof(req.path));
  req.content = ASYNC_LINE;              // doit rester valide jusqu'à DONE
  int id = smb.submit(req);
  if (id >= 0) {
    bool ok = waitAsync(id, 15000);
    Serial.printf("submit() id=%d -> %s (%s)\n", id, ok ? "OK" : "ECHEC",
                  smb.error(id).c_str());
    smb.release(id);
  } else {
    Serial.println("submit() : file pleine");
  }

  // 7) Fermeture ------------------------------------------------------------
  smb.end();
  Serial.printf("Session terminee (%lu o envoyes, %lu o recus, %lu erreur(s))\n",
                (unsigned long)smb.bytesSent(),
                (unsigned long)smb.bytesReceived(),
                (unsigned long)smb.errors());
  Serial.println("=== Fin SMB_Demo ===");
}

void loop() {
  // Rien à faire : la démonstration est entièrement dans setup().
  delay(1000);
}
