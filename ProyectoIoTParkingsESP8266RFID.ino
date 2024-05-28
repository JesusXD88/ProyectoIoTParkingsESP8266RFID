#include <string>
#include <SPI.h>
#include <MFRC522.h>
#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include <ESP8266HTTPClient.h>
#include <WebSocketsClient.h>
#include <ArduinoJson.h>
#include "arduino_secrets.h"

// Definicion de pines
#define SS_PIN    D8  // Pin del RC522 conectado al ESP8266
#define RST_PIN   D1 // Pin de reset del RC522
#define GREEN_LED D3
#define RED_LED   D4

// Definicion de endpoints
const String auth_request_endpoint = "/authcard";
const String burn_card_ws_endpoint = "/ws";
const String get_jwt_token_endpoint = "/token";

// Declaración e inicialización del JWT
String jwt_token = "";

MFRC522 mfrc522(SS_PIN, RST_PIN);
WiFiClientSecure wifiClient;
WebSocketsClient webSocket;

void setup() {
  Serial.begin(115200);
  SPI.begin();       // Iniciar SPI bus
  mfrc522.PCD_Init(); // Iniciar MFRC522

  connectWiFi();
  obtainJWT();
  connectToWebSocket();

  Serial.println("Esperando a que se acerque una tarjeta...");
}

void loop() {

  webSocket.loop();

  // Conectar a WiFi si no esta conectado
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
    obtainJWT();
    connectToWebSocket();
  }

  // Autenticar la tarjeta si hay una tarjeta presente
  if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
    // Leer el UID de la tarjeta
    String uid = getUID();
    Serial.println("UID de la tarjeta: " + uid);

    bool auth = authenticateCard(uid);

    if (auth) {
      digitalWrite(GREEN_LED, HIGH);
      Serial.println("Acceso concedido!");
      //openBarrier();
      delay(5000);
      digitalWrite(GREEN_LED, LOW);
    } else {
      digitalWrite(RED_LED, HIGH);
      Serial.println("Acceso denegado!");
      delay(5000);
      digitalWrite(RED_LED, LOW);
    }

    // Esperar a que la tarjeta se retire
    while(mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      delay(500);
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

void obtainJWT() {
  HTTPClient http;
  wifiClient.setInsecure();
  http.begin(wifiClient, "http://" + String(SECRET_BACKEND_IP) + ":" + String(SECRET_BACKEND_PORT) + get_jwt_token_endpoint);
  Serial.println("http://" + String(SECRET_BACKEND_IP) + ":" + String(SECRET_BACKEND_PORT) + get_jwt_token_endpoint);
  http.addHeader("Content-Type", "application/x-www-form-urlencoded");
  String postData = "username=" + String(SECRET_API_USER) + "&password=" + String(SECRET_API_PASS);
  int response = http.POST(postData);

  if (response > 0 ) {
    String payload = http.getString();
    Serial.println("Respuesta del servidor: " + payload);
    DynamicJsonDocument doc(1024);
    deserializeJson(doc, payload);
    jwt_token = doc["access_token"].as<String>();
  } else {
    Serial.println("Error en la solicitud HTTPS: " + String(response));
    Serial.println(http.getString());
  }
  http.end();
}

void connectToWebSocket() {
  webSocket.begin(SECRET_BACKEND_IP, SECRET_BACKEND_PORT, burn_card_ws_endpoint);
  webSocket.onEvent(webSocketEvent); // Funcion a ejecutar al recibir un evento
  webSocket.setReconnectInterval(5000); // Reintentar cada 5 segundos si la conexion 
  String authHeader = "Bearer " + jwt_token;
  webSocket.setAuthorization(authHeader.c_str()); // Agregar el token al header de autenticacion
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

bool authenticateCard(String uid) {
  HTTPClient http;
  JsonDocument doc;
  bool auth = false;
  wifiClient.setInsecure();
  String request = "http://" + String(SECRET_BACKEND_IP) + ":" + String(SECRET_BACKEND_PORT) + auth_request_endpoint + "?uid=" + uid;
  http.begin(wifiClient, request);
  http.addHeader("Authorization", "Bearer " + jwt_token);
  int response = http.GET();

  if (response > 0) {
    String payload = http.getString();
    Serial.println("Respuesta del servidor: " + payload);
    deserializeJson(doc, payload);
    auth = doc["auth"];
  } else {
    Serial.println("Error en la solicitud HTTPS: " + String(response));
  }
  http.end();
  return auth;
}

void webSocketEvent(WStype_t type, uint8_t * payload, size_t length) {
  switch(type) {
    case WStype_DISCONNECTED:
      Serial.println("WebSocket desconectado");
      break;
    case WStype_CONNECTED:
      Serial.println("WebSocket conectado");
      break;
    case WStype_BIN:
      Serial.println("Binario recibido");
      break;
    case WStype_TEXT:
      Serial.printf("Mensaje recibido: %s\n", payload);
      String action = String((char *) payload);

      if (action == "BURN_CARD") {
        DynamicJsonDocument doc(200);
        MFRC522::MIFARE_Key key;
        byte keyData[] = SECRET_RFID_KEY;
        memcpy(key.keyByte, keyData, 6);
        bool status = changeKey(1, &key);
        doc["burnSuccessful"] = status;
        if (status) {
          digitalWrite(GREEN_LED, HIGH);
          String uid = getUID();
          doc["uid"] = uid;
          delay(500);
          digitalWrite(GREEN_LED, LOW);
        } else {
          digitalWrite(RED_LED, HIGH);
          delay(500);
          digitalWrite(RED_LED, LOW);
        }
        String message;
        serializeJson(doc, message);
        webSocket.sendTXT(message);
      }
  }
}

bool changeKey(byte sector, MFRC522::MIFARE_Key *newKey) {
  MFRC522::StatusCode status;
  byte trailerBlock = sector * 4 + 3;
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF; // Llave por defecto

  // Autenticar con la llave por defecto
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Autenticación fallida: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }

  // Leer el bloque de tráiler
  byte buffer[18];
  byte size = sizeof(buffer);
  status = mfrc522.MIFARE_Read(trailerBlock, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Lectura del bloque de tráiler fallida: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false ;
  }

  // Cambiar las claves de acceso
  for (byte i = 0; i < 6; i++) buffer[i] = newKey->keyByte[i]; // Nueva clave A
  for (byte i = 10; i < 16; i++) buffer[i] = newKey->keyByte[i - 10]; // Nueva clave B

  // Escribir el nuevo bloque de tráiler
  status = mfrc522.MIFARE_Write(trailerBlock, buffer, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Escritura del bloque de tráiler fallida: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  Serial.println("Clave cambiada exitosamente");

  return true;
}

