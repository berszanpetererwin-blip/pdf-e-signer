# Modificări față de versiunea originală (pdf-e-sign v1.02)

Adaptat pentru tokenul IDEMIA IDPlug (CEI românesc) și certificate ECC.

## Corectări
- **Eroare „slot id invalid” (IDPlug):** ID-urile de slot nu sunt stabile la acest driver.
  DLL-ul PKCS#11 se încarcă o singură dată; token-ul se identifică după serial + label,
  iar slotul se re-rezolvă chiar înainte de semnare.
- **`CKR_KEY_TYPE_INCONSISTENT`:** cheile ECC (ECDSA) nu erau suportate.
  Se detectează tipul cheii (RSA/EC); pentru EC se folosește `CKM_ECDSA_SHA256`
  (fallback `CKM_ECDSA` pe digest), iar semnătura raw r||s este convertită în DER.
- **Algoritm CMS:** `endesive` marca mereu semnătura ca RSA cu HSM; pentru EC algoritmul
  este corectat în CMS (`sha256_ecdsa`). Placeholder-ul semnăturii (`aligned`) este fixat
  la 8192 pentru EC, deoarece semnăturile ECDSA au lungime variabilă.
- **Certificat/cheie:** certificatul se potrivește după conținutul DER, nu doar după `CKA_ID`
  (care poate fi gol sau duplicat); cheia privată se potrivește după tip + `CKA_ID` / modul RSA.
- Erorile hardware sunt acum scrise și în log, cu traceback.

## Îmbunătățiri
- Preset pentru driverul IDEMIA IDPlug (`idplug-pkcs11.dll`), detectare automată a driverului
  la pornire și reținerea ultimului driver ales (`last_dll` în `signature_settings.json`).
- Opțiune „Fundal transparent” pentru chenarul semnăturii.
- Motivul („Aprobat”) nu mai este afișat implicit.
- Grosime chenar cu zecimale (0.25, 0.5 ...), implicit 0.5.
- `import pymupdf as fitz` (cu fallback la `import fitz`), pentru a elimina avertismentul de depreciere.
- Dacă textul nu încape în chenarul desenat, fontul se micșorează automat (înainte PyMuPDF
  nu scria nimic, fără nicio eroare); situația este scrisă în log.

---
Bazat pe **pdf-e-signer** de ionutanton (https://github.com/ionutanton/pdf-e-signer),
licență CC BY-NC 4.0 conform README (https://creativecommons.org/licenses/by-nc/4.0/deed.ro).
Acest fork conține modificări față de original, listate mai sus.
