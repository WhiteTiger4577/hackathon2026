#include <WiFi.h>
#include "esp_wifi.h"
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>

#define MAX_APS 64
#define MAX_SSID_LEN 32

#define SERVICE_UUID        "12345678-1234-1234-1234-1234567890ab"
#define AUTH_CHAR_UUID      "12345678-1234-1234-1234-1234567890ac"
#define ALERT_CHAR_UUID     "12345678-1234-1234-1234-1234567890ad"
#define DEVICE_PASSWORD     "changeme123"
#define ALERT_LED_PIN       13
#define TABLE_SEND_INTERVAL_MS 3000

struct APRecord {
    uint8_t bssid[6];
    char ssids[10][MAX_SSID_LEN + 1];
    uint8_t ssidCount;
    uint32_t lastSeen;
    uint8_t channel;
    int8_t rssi;
};

APRecord aps[MAX_APS];

uint8_t currentChannel = 1;
uint32_t lastChannelChange = 0;
uint32_t lastTableSend = 0;

BLECharacteristic *alertCharacteristic;
bool clientAuthenticated = false;

class AuthCallback : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *characteristic) {
        String value = characteristic->getValue();
        if (value == DEVICE_PASSWORD) {
            clientAuthenticated = true;
            Serial.println("[BLE] Client authenticated");
        } else {
            clientAuthenticated = false;
            Serial.println("[BLE] Wrong password, rejecting");
        }
    }
};

class ServerCallback : public BLEServerCallbacks {
    void onDisconnect(BLEServer *server) {
        clientAuthenticated = false;
        server->getAdvertising()->start();
        Serial.println("[BLE] Client disconnected, re-advertising");
    }
};

void setupBLE() {
    BLEDevice::init("KARMA-Detector");
    BLEDevice::setMTU(247);   // allow full table rows in a single packet

    BLEServer *server = BLEDevice::createServer();
    server->setCallbacks(new ServerCallback());

    BLEService *service = server->createService(SERVICE_UUID);

    BLECharacteristic *authChar = service->createCharacteristic(
        AUTH_CHAR_UUID,
        BLECharacteristic::PROPERTY_WRITE
    );
    authChar->setCallbacks(new AuthCallback());

    alertCharacteristic = service->createCharacteristic(
        ALERT_CHAR_UUID,
        BLECharacteristic::PROPERTY_NOTIFY
    );
    alertCharacteristic->addDescriptor(new BLE2902());

    service->start();
    server->getAdvertising()->start();

    Serial.println("[BLE] Advertising as KARMA-Detector");
}

void sendBLEMessage(const char *msg) {
    if (!clientAuthenticated) return;
    alertCharacteristic->setValue((uint8_t *)msg, strlen(msg));
    alertCharacteristic->notify();
    delay(20);   // give the BLE stack breathing room between packets
}

void printMac(const uint8_t *mac, char *out) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int findAP(const uint8_t *bssid) {
    for (int i = 0; i < MAX_APS; i++) {
        if (aps[i].ssidCount > 0 && memcmp(aps[i].bssid, bssid, 6) == 0)
            return i;
    }
    return -1;
}

int findFreeAP() {
    for (int i = 0; i < MAX_APS; i++) {
        if (aps[i].ssidCount == 0)
            return i;
    }
    return -1;
}

bool hasSSID(APRecord &ap, const char *ssid) {
    for (int i = 0; i < ap.ssidCount; i++) {
        if (strcmp(ap.ssids[i], ssid) == 0)
            return true;
    }
    return false;
}

void processSSID(const uint8_t *bssid, const char *ssid, uint8_t channel, int8_t rssi) {
    if (ssid == nullptr) return;
    if (ssid[0] == '\0') return;

    int index = findAP(bssid);

    if (index < 0) {
        index = findFreeAP();
        if (index < 0) return;

        memset(&aps[index], 0, sizeof(APRecord));
        memcpy(aps[index].bssid, bssid, 6);
    }

    aps[index].lastSeen = millis();
    aps[index].channel = channel;
    aps[index].rssi = rssi;

    if (hasSSID(aps[index], ssid))
        return;

    if (aps[index].ssidCount < 10) {
        strncpy(aps[index].ssids[aps[index].ssidCount], ssid, MAX_SSID_LEN);
        aps[index].ssids[aps[index].ssidCount][MAX_SSID_LEN] = '\0';
        aps[index].ssidCount++;

        if (aps[index].ssidCount > 1) {
            digitalWrite(ALERT_LED_PIN, 1);
        }
    }
}

// ------------------------------------------------------------
// Streams the current table to the app as CLR / ROW.. / SUM
// ------------------------------------------------------------

void sendNetworkTableBLE() {
    if (!clientAuthenticated) return;

    int totalBSSIDs = 0;
    int totalSSIDs = 0;
    int suspiciousBSSIDs = 0;

    for (int i = 0; i < MAX_APS; i++) {
        if (aps[i].ssidCount == 0) continue;
        totalBSSIDs++;
        totalSSIDs += aps[i].ssidCount;
        if (aps[i].ssidCount > 1) suspiciousBSSIDs++;
    }

    sendBLEMessage("CLR");

    for (int i = 0; i < MAX_APS; i++) {
        if (aps[i].ssidCount == 0) continue;

        char bssidStr[18];
        printMac(aps[i].bssid, bssidStr);
        bool isRisk = (aps[i].ssidCount > 1);

        for (int j = 0; j < aps[i].ssidCount; j++) {
            char row[140];
            snprintf(row, sizeof(row), "ROW|%s|%d|%d|%s|%d",
                     bssidStr, aps[i].channel, aps[i].rssi,
                     aps[i].ssids[j], isRisk ? 1 : 0);
            sendBLEMessage(row);
        }
    }

    char summary[64];
    snprintf(summary, sizeof(summary), "SUM|%d|%d|%d",
              totalBSSIDs, totalSSIDs, suspiciousBSSIDs);
    sendBLEMessage(summary);
}

// Also keep the same table printed to Serial, handy for debugging
void printNetworkTableSerial() {
    int totalBSSIDs = 0, totalSSIDs = 0, suspiciousBSSIDs = 0;
    for (int i = 0; i < MAX_APS; i++) {
        if (aps[i].ssidCount == 0) continue;
        totalBSSIDs++;
        totalSSIDs += aps[i].ssidCount;
        if (aps[i].ssidCount > 1) suspiciousBSSIDs++;
    }

    Serial.println();
    Serial.println("============================================================");
    Serial.println("                    WIFI NETWORKS");
    Serial.println("============================================================");
    Serial.println("BSSID              CH   RSSI   SSID");
    Serial.println("------------------------------------------------------------");

    for (int i = 0; i < MAX_APS; i++) {
        if (aps[i].ssidCount == 0) continue;
        char bssidStr[18];
        printMac(aps[i].bssid, bssidStr);
        bool isRisk = (aps[i].ssidCount > 1);

        for (int j = 0; j < aps[i].ssidCount; j++) {
            Serial.printf("%-18s %2d   %4d   %-28s%s\n",
                          bssidStr, aps[i].channel, aps[i].rssi,
                          aps[i].ssids[j], isRisk ? " [!]" : "");
        }
    }

    Serial.println("------------------------------------------------------------");
    Serial.printf("BSSIDs: %d | SSIDs: %d | Suspicious BSSIDs: %d\n",
                  totalBSSIDs, totalSSIDs, suspiciousBSSIDs);
    Serial.println("============================================================");
}

void wifiSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *payload = packet->payload;

    uint16_t frameControl = payload[0] | ((uint16_t)payload[1] << 8);
    uint8_t frameType = (frameControl >> 2) & 0x03;
    uint8_t frameSubtype = (frameControl >> 4) & 0x0F;

    if (frameType != 0) return;
    if (frameSubtype != 8 && frameSubtype != 5) return;

    uint8_t *bssid = &payload[16];
    int8_t rssi = packet->rx_ctrl.rssi;

    int offset = 36;
    int packetLength = packet->rx_ctrl.sig_len;

    while (offset + 2 <= packetLength) {
        uint8_t elementID = payload[offset];
        uint8_t elementLength = payload[offset + 1];

        if (offset + 2 + elementLength > packetLength) break;

        if (elementID == 0) {
            char ssid[MAX_SSID_LEN + 1];
            uint8_t copyLength = min(elementLength, (uint8_t)MAX_SSID_LEN);

            memcpy(ssid, &payload[offset + 2], copyLength);
            ssid[copyLength] = '\0';

            processSSID(bssid, ssid, currentChannel, rssi);
            break;
        }

        offset += 2 + elementLength;
    }
}

void setup() {
    Serial.begin(115200);
    delay(1000);

    pinMode(ALERT_LED_PIN, OUTPUT);

    Serial.println();
    Serial.println("========================================");
    Serial.println(" ESP32-S3 Karma Detector + BLE Alerts");
    Serial.println("========================================");

    WiFi.mode(WIFI_MODE_STA);
    WiFi.disconnect();
    delay(100);

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifiSniffer);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    lastChannelChange = millis();
    lastTableSend = millis();

    Serial.println("[+] Promiscuous mode enabled");
    Serial.println("[+] Scanning Wi-Fi channels...");

    setupBLE();
}

void loop() {
    if (millis() - lastChannelChange >= 250) {
        currentChannel++;
        if (currentChannel > 13) currentChannel = 1;

        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        lastChannelChange = millis();
    }

    if (millis() - lastTableSend >= TABLE_SEND_INTERVAL_MS) {
        printNetworkTableSerial();
        sendNetworkTableBLE();
        lastTableSend = millis();
    }

    delay(10);
}