#include <string>
#include <SPI.h>
#include <MFRC522.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include "arduino_secrets.h"

#define SS_PIN D8  // Pin del RC522 conectado al ESP8266
#define RST_PIN D1 // Pin de reset del RC522

// Definicion de endpoints
const String com_request_endpoint = "/card";

MFRC522 mfrc522(SS_PIN, RST_PIN);
WiFiClient wifiClient;

void setup() {
  Serial.begin(115200);
  SPI.begin();       // Iniciar SPI bus
  mfrc522.PCD_Init(); // Iniciar MFRC522

  connectWiFi();

  Serial.println("Esperando a que se acerque una tarjeta...");
}

void loop() {

  // Conectar a WiFi si no esta conectado
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  // Revisar si hay una nueva tarjeta presente
  if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
    // Leer el UID de la tarjeta
    String uid = getUID();
    Serial.println("UID de la tarjeta: " + uid);

    // Realizar peticion para recibir comandos remotos
    while (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      if (WiFi.status() == WL_CONNECTED) {
        HTTPClient http;
        String requestUrl = String(SECRET_BACKEND_URL) + com_request_endpoint + "?uid=" + uid;
        http.begin(wifiClient, requestUrl);
        int httpCode = http.GET();

        if (httpCode > 0) {
          String payload = http.getString();
          Serial.println("Respuesta del servidor: " + payload);

          if (payload == "ACCESS_GRANTED") {
            digitalWrite(D1, HIGH);
            delay(2000);
            digitalWrite(D1, LOW);
          } else if (payload == "CHANGE_KEY") {
            MFRC522::MIFARE_Key newKey;
            byte newKeyData[] = SECRET_RFID_KEY;
            memcpy(newKey.keyByte, newKeyData, 6);
            changeKey(1, &newKey);
            digitalWrite(D1, HIGH);
            delay(2000);
            digitalWrite(D1, LOW);
          } else {
            digitalWrite(D2, HIGH);
            delay(2000);
            digitalWrite(D2, LOW);
          }
        } else {
          Serial.println("Error en la solicitud HTTP: " + String(httpCode));
        }
        http.end();
      } else {
        Serial.println("WiFi no está conectado");
      }
      delay(1000); // Esperar un segundo antes de enviar la próxima solicitud
    }

    // Detener la comunicación con la tarjeta
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
  }

}

void connectWiFi() {
  WiFi.begin(SECRET_SSID, SECRET_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Conectando a WiFi...");
  }
  Serial.println("Conectado a WiFi");
}

String getUID() {
  String uid = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    uid += String(mfrc522.uid.uidByte[i] < 0x10 ? "0" : "");
    uid += String(mfrc522.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();
  return uid;
}

void changeKey(byte sector, MFRC522::MIFARE_Key *newKey) {
  MFRC522::StatusCode status;
  byte trailerBlock = sector * 4 + 3;
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF; // Llave por defecto

  // Autenticar con la llave por defecto
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Autenticación fallida: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // Leer el bloque de tráiler
  byte buffer[18];
  byte size = sizeof(buffer);
  status = mfrc522.MIFARE_Read(trailerBlock, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Lectura del bloque de tráiler fallida: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // Cambiar las claves de acceso
  for (byte i = 0; i < 6; i++) buffer[i] = newKey->keyByte[i]; // Nueva clave A
  for (byte i = 10; i < 16; i++) buffer[i] = newKey->keyByte[i - 10]; // Nueva clave B

  // Escribir el nuevo bloque de tráiler
  status = mfrc522.MIFARE_Write(trailerBlock, buffer, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Escritura del bloque de tráiler fallida: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  Serial.println("Clave cambiada exitosamente");
}

