#include <WiFi.h>
#include <WebServer.h>

// ============================================================
// Configuration
// ============================================================

#define AP_SSID       "ESP32-Karma-Detector"
#define AP_PASSWORD   "detect1234"

#define MAX_APS       64
#define MAX_SSIDS     10
#define MAX_SSID_LEN  32

#define SCAN_INTERVAL 3000


// ============================================================
// Web server
// ============================================================

WebServer server(80);


// ============================================================
// AP database
// ============================================================

struct APRecord {

    uint8_t bssid[6];

    char ssids[MAX_SSIDS][MAX_SSID_LEN + 1];

    uint8_t ssidCount;

    int32_t rssi;

    int channel;

    uint32_t lastSeen;
};


APRecord aps[MAX_APS];

int apCount = 0;

uint32_t lastScan = 0;


// ============================================================
// Mutex
// ============================================================

portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;


// ============================================================
// Utility
// ============================================================

String macToString(const uint8_t *mac)
{
    char buffer[18];

    snprintf(
        buffer,
        sizeof(buffer),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );

    return String(buffer);
}


// ============================================================
// Find AP by BSSID
// ============================================================

int findAP(const uint8_t *bssid)
{
    for (int i = 0; i < apCount; i++) {

        if (memcmp(
                aps[i].bssid,
                bssid,
                6
            ) == 0) {

            return i;
        }
    }

    return -1;
}


// ============================================================
// Check whether SSID already exists
// ============================================================

bool hasSSID(
    APRecord &ap,
    const char *ssid
)
{
    for (int i = 0; i < ap.ssidCount; i++) {

        if (strcmp(
                ap.ssids[i],
                ssid
            ) == 0) {

            return true;
        }
    }

    return false;
}


// ============================================================
// Add SSID to AP record
// ============================================================

void addSSID(
    APRecord &ap,
    const char *ssid
)
{
    if (ssid == nullptr)
        return;

    if (ssid[0] == '\0')
        return;

    if (hasSSID(ap, ssid))
        return;

    if (ap.ssidCount >= MAX_SSIDS)
        return;

    strncpy(
        ap.ssids[ap.ssidCount],
        ssid,
        MAX_SSID_LEN
    );

    ap.ssids[ap.ssidCount][MAX_SSID_LEN] = '\0';

    ap.ssidCount++;
}


// ============================================================
// Process scan result
// ============================================================

void processNetwork(
    const uint8_t *bssid,
    const char *ssid,
    int rssi,
    int channel
)
{
    if (ssid == nullptr)
        return;

    // Ignore hidden networks.
    if (ssid[0] == '\0')
        return;


    int index = findAP(bssid);


    // --------------------------------------------------------
    // New BSSID
    // --------------------------------------------------------

    if (index < 0) {

        if (apCount >= MAX_APS)
            return;

        index = apCount++;

        memset(
            &aps[index],
            0,
            sizeof(APRecord)
        );

        memcpy(
            aps[index].bssid,
            bssid,
            6
        );
    }


    // --------------------------------------------------------
    // Update information
    // --------------------------------------------------------

    aps[index].rssi = rssi;

    aps[index].channel = channel;

    aps[index].lastSeen = millis();


    addSSID(
        aps[index],
        ssid
    );
}


// ============================================================
// Perform Wi-Fi scan
// ============================================================

void performScan()
{
    Serial.println();
    Serial.println("[SCAN] Starting Wi-Fi scan...");


    // --------------------------------------------------------
    // Scan all channels
    // --------------------------------------------------------

    int networkCount =
        WiFi.scanNetworks(
            false,   // async
            true     // show hidden
        );


    if (networkCount < 0) {

        Serial.println(
            "[SCAN] Scan failed"
        );

        return;
    }


    // --------------------------------------------------------
    // Clear previous database
    // --------------------------------------------------------

    portENTER_CRITICAL(&mux);

    memset(
        aps,
        0,
        sizeof(aps)
    );

    apCount = 0;

    portEXIT_CRITICAL(&mux);


    // --------------------------------------------------------
    // Process results
    // --------------------------------------------------------

    for (int i = 0; i < networkCount; i++) {

        String ssid =
            WiFi.SSID(i);

        int rssi =
            WiFi.RSSI(i);

        int channel =
            WiFi.channel(i);


        uint8_t *bssid =
            WiFi.BSSID(i);


        if (bssid == nullptr)
            continue;


        portENTER_CRITICAL(&mux);

        processNetwork(
            bssid,
            ssid.c_str(),
            rssi,
            channel
        );

        portEXIT_CRITICAL(&mux);
    }


    WiFi.scanDelete();


    Serial.print(
        "[SCAN] Found "
    );

    Serial.print(
        apCount
    );

    Serial.println(
        " BSSIDs"
    );


    // --------------------------------------------------------
    // Serial output
    // --------------------------------------------------------

    for (int i = 0; i < apCount; i++) {

        Serial.print(
            macToString(
                aps[i].bssid
            )
        );

        Serial.print(
            " | CH "
        );

        Serial.print(
            aps[i].channel
        );

        Serial.print(
            " | RSSI "
        );

        Serial.print(
            aps[i].rssi
        );

        Serial.print(
            " | SSIDs: "
        );

        for (
            int j = 0;
            j < aps[i].ssidCount;
            j++
        ) {

            if (j > 0)
                Serial.print(", ");

            Serial.print(
                aps[i].ssids[j]
            );
        }

        if (aps[i].ssidCount >= 2)
            Serial.print(
                "  <-- SUSPICIOUS"
            );

        Serial.println();
    }
}


// ============================================================
// Generate webpage
// ============================================================

void handleRoot()
{
    String html;

    html.reserve(16000);


    // --------------------------------------------------------
    // HTML header
    // --------------------------------------------------------

    html += R"rawliteral(
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,
               initial-scale=1.0">

<meta http-equiv="refresh"
      content="3">

<title>ESP32 Wi-Fi Detector</title>

<style>

body {
    background: #111;
    color: #eee;
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 20px;
}

h1 {
    margin-top: 0;
}

.info {
    color: #aaa;
    margin-bottom: 20px;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: #1b1b1b;
}

th {
    background: #292929;
    padding: 10px;
    text-align: left;
}

td {
    padding: 10px;
    border-bottom: 1px solid #333;
}

.suspicious {
    background: #500000;
    color: #fff;
}

.suspicious td {
    border-bottom: 1px solid #800000;
}

.warning {
    color: #ff4444;
    font-weight: bold;
}

.normal {
    color: #ddd;
}

.ssid {
    display: block;
    margin: 3px 0;
}

</style>

</head>

<body>

<h1>ESP32 Wi-Fi Detector</h1>

<div class="info">

AP:
<strong>ESP32-Karma-Detector</strong>

<br>

Networks detected:
<strong>
)rawliteral";


    html += String(apCount);


    html += R"rawliteral(
</strong>

<br>

Page automatically refreshes every 3 seconds.

</div>

<table>

<tr>
<th>SSID</th>
<th>BSSID</th>
<th>Channel</th>
<th>RSSI</th>
<th>Status</th>
</tr>

)rawliteral";


    // --------------------------------------------------------
    // Network rows
    // --------------------------------------------------------

    portENTER_CRITICAL(&mux);


    for (int i = 0; i < apCount; i++) {

        bool suspicious =
            aps[i].ssidCount >= 2;


        String rowClass =
            suspicious
                ? "suspicious"
                : "normal";


        String mac =
            macToString(
                aps[i].bssid
            );


        // One row for each SSID.

        for (
            int j = 0;
            j < aps[i].ssidCount;
            j++
        ) {

            html += "<tr class=\"";
            html += rowClass;
            html += "\">";


            // SSID

            html += "<td>";

            html +=
                aps[i].ssids[j];

            html += "</td>";


            // BSSID

            html += "<td>";

            html += mac;

            html += "</td>";


            // Channel

            html += "<td>";

            html +=
                String(
                    aps[i].channel
                );

            html += "</td>";


            // RSSI

            html += "<td>";

            html +=
                String(
                    aps[i].rssi
                );

            html += " dBm</td>";


            // Status

            html += "<td>";

            if (suspicious) {

                html +=
                    "<span class=\"warning\">";

                html +=
                    "SUSPICIOUS";

                html +=
                    "</span>";

            } else {

                html +=
                    "Normal";
            }

            html += "</td>";


            html += "</tr>";
        }
    }


    portEXIT_CRITICAL(&mux);


    // --------------------------------------------------------
    // HTML footer
    // --------------------------------------------------------

    html += R"rawliteral(

</table>

</body>

</html>

)rawliteral";


    server.send(
        200,
        "text/html",
        html
    );
}


// ============================================================
// 404
// ============================================================

void handleNotFound()
{
    server.send(
        404,
        "text/plain",
        "Not found"
    );
}


// ============================================================
// Start Access Point
// ============================================================

void setupAccessPoint()
{
    Serial.println();
    Serial.println(
        "[AP] Starting access point..."
    );


    WiFi.mode(
        WIFI_AP_STA
    );


    bool success =
        WiFi.softAP(
            AP_SSID,
            AP_PASSWORD
        );


    if (!success) {

        Serial.println(
            "[AP] FAILED"
        );

        return;
    }


    Serial.println(
        "[AP] Started"
    );


    Serial.print(
        "[AP] SSID: "
    );

    Serial.println(
        AP_SSID
    );


    Serial.print(
        "[AP] IP: "
    );

    Serial.println(
        WiFi.softAPIP()
    );
}


// ============================================================
// Start web server
// ============================================================

void setupWebServer()
{
    server.on(
        "/",
        HTTP_GET,
        handleRoot
    );


    server.onNotFound(
        handleNotFound
    );


    server.begin();


    Serial.println(
        "[HTTP] Web server started"
    );
}


// ============================================================
// Setup
// ============================================================

void setup()
{
    Serial.begin(
        115200
    );


    delay(1000);


    Serial.println();
    Serial.println(
        "========================================"
    );

    Serial.println(
        " ESP32-S3 Wi-Fi Detector"
    );

    Serial.println(
        "========================================"
    );


    // --------------------------------------------------------
    // Start AP
    // --------------------------------------------------------

    setupAccessPoint();


    // --------------------------------------------------------
    // Start HTTP server
    // --------------------------------------------------------

    setupWebServer();


    // --------------------------------------------------------
    // Initial scan
    // --------------------------------------------------------

    performScan();


    lastScan =
        millis();


    Serial.println();

    Serial.println(
        "[+] Detector ready"
    );

    Serial.print(
        "[+] Connect to: "
    );

    Serial.println(
        AP_SSID
    );

    Serial.println(
        "[+] Open http://192.168.4.1/"
    );
}


// ============================================================
// Main loop
// ============================================================

void loop()
{
    // Handle web requests.
    server.handleClient();


    // Periodic scan.
    if (
        millis() - lastScan >=
        SCAN_INTERVAL
    ) {

        lastScan =
            millis();

        performScan();
    }


    delay(5);
}