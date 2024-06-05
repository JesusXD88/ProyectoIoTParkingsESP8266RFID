#include <string>
#include <SPI.h>
#include <MFRC522.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecure.h>
#include <WebSocketsClient.h>
#include <ArduinoJson.h>
#include <Servo.h>
#include "arduino_secrets.h"

// Definicion de pines
#define SS_PIN D8     // Pin del RC522 conectado al ESP8266
#define RST_PIN D1    // Pin de reset del RC522
#define GREEN_LED D3  // Pin del LED verde
#define RED_LED D4    // Pin del LED rojo
#define SERVO_PIN D0  // Pin del ServoMotor

// Declaración del fingerprint
uint8_t fingerprint[20];

// Declaración e inicialización del JWT
String jwt_token = "";

MFRC522 mfrc522(SS_PIN, RST_PIN);
WiFiClientSecure wifiClient;
//WiFiClient wifiClient;
WebSocketsClient webSocket;

Servo servoMotor;

// Declaracion e inicializacion del tiempo de apertura
int open_sec = 10;

// Variables para el tiempo de la última lectura de tarjeta
unsigned long lastCardReadTime = 0;
const unsigned long cardReadInterval = 3000;

void setup() {
  Serial.begin(115200);
  Serial.setDebugOutput(true);

  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  digitalWrite(GREEN_LED, HIGH);
  digitalWrite(RED_LED, HIGH);
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);

  SPI.begin();         // Iniciar SPI bus
  mfrc522.PCD_Init();  // Iniciar MFRC522

  // Convertir el fingerprint
  convertFingerprint(SECRET_CERT_FINGERPRINT, fingerprint);
  wifiClient.setFingerprint(fingerprint);

  connectWiFi();
  obtainJWT();
  connectToWebSocket();

  servoMotor.attach(SERVO_PIN);

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

    unsigned long currentTime = millis();
    if (currentTime - lastCardReadTime >= cardReadInterval) {
      lastCardReadTime = currentTime;

      // Enviar el UID al servidor a través de WebSocket
      sendAuthRequest(uid);

      // Esperar a que la tarjeta se retire
      while(mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
        delay(500);
      }

      // Detener la comunicación con la tarjeta
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();
    } else {
      Serial.println("Esperando antes de permitir otra lectura de tarjeta.");
    }
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
  WiFiClientSecure tempClient;
  tempClient.setFingerprint(fingerprint);

  HTTPClient http;
  http.begin(tempClient, "https://" + String(SECRET_BACKEND_IP) + ":" + String(SECRET_BACKEND_PORT) + "/token");
  Serial.println("https://" + String(SECRET_BACKEND_IP) + ":" + String(SECRET_BACKEND_PORT) + "/token");
  http.addHeader("Content-Type", "application/x-www-form-urlencoded");
  String postData = "username=" + String(SECRET_API_USER) + "&password=" + String(SECRET_API_PASS);
  int response = http.POST(postData);

  if (response > 0) {
    String payload = http.getString();
    Serial.println("Respuesta del servidor: " + payload);
    StaticJsonDocument<512> doc;
    deserializeJson(doc, payload);
    jwt_token = doc["access_token"].as<String>();
  } else {
    Serial.println("Error en la solicitud http:: " + String(response));
    Serial.println(http.getString());
    digitalWrite(RED_LED, HIGH);
    delay(100);
    digitalWrite(RED_LED, LOW);
    delay(700);
    digitalWrite(RED_LED, HIGH);
    delay(100);
    digitalWrite(RED_LED, LOW);
  }
  http.end();
  tempClient.stop();
}

void connectToWebSocket() {
  String wsURL = "/ws?token=" + jwt_token;

  // Reiniciar WiFiClientSecure
  wifiClient.stop();
  new (&wifiClient) WiFiClientSecure;
  wifiClient.setFingerprint(fingerprint);

  webSocket.beginSSL(SECRET_BACKEND_IP, SECRET_BACKEND_PORT, wsURL.c_str(), fingerprint);
  webSocket.onEvent(webSocketEvent);
  webSocket.setReconnectInterval(5000);
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

void sendAuthRequest(String uid) {
  DynamicJsonDocument doc(200);
  doc["action"] = "AUTH_CARD";
  doc["uid"] = uid;
  String message;
  serializeJson(doc, message);
  webSocket.sendTXT(message);
}

void openBarrier() {
  Serial.println("Abriendo barrera");
  servoMotor.write(0);
  delay(1000 * open_sec);
  servoMotor.write(120);
}

void webSocketEvent(WStype_t type, uint8_t *payload, size_t length) {
  switch (type) {
    case WStype_DISCONNECTED:
      Serial.println("WebSocket desconectado");
      digitalWrite(RED_LED, HIGH);
      delay(100);
      digitalWrite(RED_LED, LOW);
      delay(700);
      digitalWrite(RED_LED, HIGH);
      delay(100);
      digitalWrite(RED_LED, LOW);
      delay(700);
      digitalWrite(RED_LED, HIGH);
      digitalWrite(RED_LED, LOW);
      break;
    case WStype_CONNECTED:
      Serial.println("WebSocket conectado");
      digitalWrite(GREEN_LED, HIGH);
      delay(100);
      digitalWrite(GREEN_LED, LOW);
      delay(700);
      digitalWrite(GREEN_LED, HIGH);
      delay(100);
      digitalWrite(GREEN_LED, LOW);
      delay(700);
      digitalWrite(GREEN_LED, HIGH);
      digitalWrite(GREEN_LED, LOW);
      break;
    case WStype_TEXT:
      Serial.printf("Mensaje recibido: %s\n", payload);
      handleWebSocketMessage((char *)payload, length);
      break;
    case WStype_BIN:
      Serial.println("Binario recibido");
      break;
  }
}

void handleWebSocketMessage(const char* message, size_t length) {
  DynamicJsonDocument doc(512);
  Serial.println(message);
  DeserializationError error = deserializeJson(doc, message, length);
  if (error) {
    Serial.print(F("deserializeJson() falló: "));
    Serial.println(error.c_str());
    return;
  }

  const char* action = doc["action"];
  if (strcmp(action, "AUTH_RESPONSE") == 0) {
    bool auth = doc["auth"];
    int barrier_open_sec = doc["barrier_open_sec"];
    open_sec = barrier_open_sec;

    if (auth) {
      digitalWrite(GREEN_LED, HIGH);
      Serial.println("Acceso concedido!");
      openBarrier();
      digitalWrite(GREEN_LED, LOW);
    } else {
      digitalWrite(RED_LED, HIGH);
      Serial.println("Acceso denegado!");
      delay(1000);
      digitalWrite(RED_LED, LOW);
    }
  } else if (strcmp(action, "BURN_CARD") == 0) {
    handleBurnCard();
  } else if (strcmp(action, "OPEN_BARRIER") == 0) {
    int barrier_open_sec = doc["barrier_open_sec"];
    open_sec = barrier_open_sec;
    digitalWrite(GREEN_LED, HIGH);
    Serial.println("Barrera abierta manualmente");
    openBarrier();
    digitalWrite(GREEN_LED, LOW);
  }
}

void handleBurnCard() {
  Serial.println("Acerca la tarjeta al lector");
  DynamicJsonDocument doc(200);
  MFRC522::MIFARE_Key key;
  byte keyData[] = SECRET_RFID_KEY;
  memcpy(key.keyByte, keyData, 6);
  bool status = changeKey(1, &key);
  Serial.println("Cambio de llave hecho (bien o mal)");
  doc["action"] = "BURN_RESPONSE";
  doc["burnSuccessful"] = status;
  if (status) {
    digitalWrite(GREEN_LED, HIGH);
    String uid = getUID();
    doc["uid"] = uid;
    delay(5000);
    digitalWrite(GREEN_LED, LOW);
  } else {
    digitalWrite(RED_LED, HIGH);
    delay(5000);
    digitalWrite(RED_LED, LOW);
  }
  String message;
  serializeJson(doc, message);
  Serial.println("Mensaje: " + message);
  webSocket.sendTXT(message);
  delay(1000);
}

bool changeKey(byte sector, MFRC522::MIFARE_Key *newKey) {
  while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    delay(100);
  }

  MFRC522::StatusCode status;
  byte trailerBlock = sector * 4 + 3;
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;  // Llave por defecto

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
    return false;
  }

  // Cambiar las claves de acceso
  for (byte i = 0; i < 6; i++) buffer[i] = newKey->keyByte[i];         // Nueva clave A
  for (byte i = 10; i < 16; i++) buffer[i] = newKey->keyByte[i - 10];  // Nueva clave B

  // Escribir el nuevo bloque de tráiler
  status = mfrc522.MIFARE_Write(trailerBlock, buffer, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Escritura del bloque de tráiler fallida: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  Serial.println("Clave cambiada exitosamente");

  // Detener la comunicación con la tarjeta
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  return true;
}

void convertFingerprint(const char* fingerprintStr, uint8_t* fingerprint) {
  for (int i = 0; i < 20; i++) {
    char hex[3];
    hex[0] = fingerprintStr[i * 2];
    hex[1] = fingerprintStr[i * 2 + 1];
    hex[2] = '\0';
    fingerprint[i] = strtol(hex, nullptr, 16);
  }
}
