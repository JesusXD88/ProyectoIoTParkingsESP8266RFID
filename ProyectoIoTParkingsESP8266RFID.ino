#include <string>
#include <SPI.h>
#include <MFRC522.h>
#include <ESP8266WiFi.h>
#include "arduino_secrets.h"

#define SS_PIN D8  // Pin del RC522 conectado al ESP8266
#define RST_PIN D1 // Pin de reset del RC522

MFRC522 mfrc522(SS_PIN, RST_PIN);

void setup() {
  Serial.begin(115200);
  SPI.begin();       // Iniciar SPI bus
  mfrc522.PCD_Init(); // Iniciar MFRC522

  WiFi.begin(SECRET_SSID, SECRET_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Conectando a la red WiFi...");
  }
  Serial.println("Conectado a la red WiFi: " + String(SECRET_SSID));

  Serial.println("Esperando a que se acerque una tarjeta...");
}

void loop() {
  // Revisar si hay una nueva tarjeta presente
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    delay(50);
    return;
  }

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

