import tkinter as tk
from tkinter import ttk, filedialog, messagebox, colorchooser
import threading
import os
import logging
import datetime
import traceback
import json
import platform
from pathlib import Path
from dataclasses import dataclass
from typing import Tuple
from PIL import Image, ImageTk
try:
    import pymupdf as fitz  # PyMuPDF (API nou)
except ImportError:
    import fitz  # PyMuPDF (versiuni vechi)
from tkinterdnd2 import DND_FILES, TkinterDnD

import PyKCS11
from endesive.pdf import cms
from endesive import signer as _endesive_signer
from asn1crypto import cms as _asn1_cms, algos as _asn1_algos
from cryptography.hazmat.primitives.asymmetric import ec as _ec, rsa as _rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# --- PLATFORMĂ ---
IS_WINDOWS = platform.system() == "Windows"

# --- CONFIGURARE LOGGING ---
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

if logger.hasHandlers():
    logger.handlers.clear()

file_handler = logging.FileHandler("app_debug.log", encoding="utf-8", mode='w')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

SETTINGS_FILE = "signature_settings.json"

DEFAULT_SETTINGS = {
    "contact": "",
    "location": "România",
    "reason": "",
    "bg_color": "#ffffff",
    "transparent_bg": False,
    "outline_color": "#000000",
    "border": 0.5,
    "display_cn": True,
    "display_date": True,
    "display_reason": False,
    "display_location": False,
    "display_contact": False,
    "fontsize": 8,
    "textalign": "left",
    "linespacing": 1.2,
    "lbl_cn": "",
    "lbl_date": "",
    "lbl_reason": "Motiv:",
    "lbl_loc": "",
    "lbl_contact": "",
    "use_image": False,
    "image_path": ""
}

# --- PROFILURI DRIVERE PKCS#11 ---
if IS_WINDOWS:
    _PF = os.environ.get("ProgramFiles", r"C:\Program Files")
    _PF86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    DLL_PRESETS = {
        "IDEMIA / IDPlug (idplug-pkcs11.dll)": os.path.join(_PF, "IDEMIA", "IDPlugClassic", "DLLs", "idplug-pkcs11.dll"),
        "IDEMIA / IDPlug x86 (idplug-pkcs11.dll)": os.path.join(_PF86, "IDEMIA", "IDPlugClassic", "DLLs", "idplug-pkcs11.dll"),
        "Alfasign / SafeNet (eToken.dll)": r"C:\Windows\System32\eToken.dll",
        "DigiSign / SafeNet (eToken.dll)": r"C:\Windows\System32\eToken.dll",
        "DigiSign / ePass2003 (eps2003csp11.dll)": r"C:\Windows\System32\eps2003csp11.dll",
        "certSign / SafeNet (eToken.dll)": r"C:\Windows\System32\eToken.dll",
        "certSIGN / Athena (acpkcs211.dll)": r"C:\Windows\System32\acpkcs211.dll",
        "certSIGN / Bit4Id (bit4xpki.dll)": r"C:\Windows\System32\bit4xpki.dll",
        "certSIGN / Oberthur (OcsCryptoki.dll)": r"C:\Windows\System32\OcsCryptoki.dll",
        "CertDigital / Bit4Id (bit4xpki.dll)": r"C:\Windows\System32\bit4xpki.dll"
    }
    DEFAULT_DLL = "Alfasign / SafeNet (eToken.dll)"
else:
    # Linux / Ubuntu
    DLL_PRESETS = {
        "Alfasign / SafeNet (libeToken.so)":       "/usr/lib/libeToken.so",
        "DigiSign / SafeNet (libeToken.so)":        "/usr/lib/libeToken.so",
        "DigiSign / ePass2003 (libepsng_p11.so)":   "/usr/lib/libepsng_p11.so",
        "certSIGN / Athena (libacpkcs211.so)":      "/usr/lib/libacpkcs211.so",
        "certSIGN / Bit4Id (libbit4xpki.so)":       "/usr/lib/libbit4xpki.so",
        "certSIGN / Oberthur (libocscryptoki.so)":  "/usr/lib/libocscryptoki.so",
        "CertDigital / Bit4Id (libbit4xpki.so)":    "/usr/lib/libbit4xpki.so",
        "OpenSC (opensc-pkcs11.so)":                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    }
    DEFAULT_DLL = "Alfasign / SafeNet (libeToken.so)"

def hex_to_rgb(hex_str):
    hex_str = hex_str.lstrip('#')
    if len(hex_str) != 6: return [0.0, 0.0, 0.0]
    return [int(hex_str[i:i+2], 16) / 255.0 for i in (0, 2, 4)]

_orig_endesive_sign = _endesive_signer.sign

def _patched_endesive_sign(*args, **kwargs):
    """endesive marchează mereu semnătura ca RSA când se folosește un HSM.
    Pentru chei EC corectăm algoritmul în CMS (semnătura rămâne validă, deoarece
    algoritmul nu face parte din atributele semnate)."""
    out = _orig_endesive_sign(*args, **kwargs)
    hsm = kwargs.get('hsm', args[7] if len(args) > 7 else None)
    if hsm is not None and getattr(hsm, 'key_type', 'rsa') == 'ec':
        hashalgo = kwargs.get('hashalgo', args[4] if len(args) > 4 else 'sha256')
        ci = _asn1_cms.ContentInfo.load(out)
        si = ci['content']['signer_infos'][0]
        si['signature_algorithm'] = _asn1_algos.SignedDigestAlgorithm({'algorithm': f'{hashalgo}_ecdsa'})
        out = ci.dump(force=True)
    return out

_endesive_signer.sign = _patched_endesive_sign


class HardwareTokenHSM:
    """Gestionarea Hardware-ului (PKCS#11) cu suport Universal Multi-Token.

    IMPORTANT (fix IDPlug / IDEMIA): ID-urile de slot NU sunt stabile la unele
    drivere PKCS#11 (IDPlug, unele SafeNet). Se pot schimba la fiecare
    C_Initialize / reîncărcare a DLL-ului sau la reintroducerea token-ului.
    De aceea:
      * DLL-ul se încarcă o singură dată per proces (cache), nu la fiecare acțiune;
      * token-ul se identifică prin serialNumber + label, iar slotul se
        RE-REZOLVĂ chiar înainte de semnare;
      * certificatul se identifică prin conținutul lui (DER), nu doar prin CKA_ID
        (care poate fi gol sau duplicat).
    """

    _LIBS = {}

    @classmethod
    def _get_lib(cls, dll_path, force_reload=False):
        key = os.path.normcase(os.path.abspath(dll_path))
        if force_reload and key in cls._LIBS:
            old = cls._LIBS.pop(key)
            try:
                old.lib.C_Finalize()
            except Exception:
                pass
            del old
        lib = cls._LIBS.get(key)
        if lib is None:
            if not os.path.exists(dll_path):
                raise FileNotFoundError(f"Fișierul driver nu a fost găsit la: {dll_path}")
            lib = PyKCS11.PyKCS11Lib()
            try:
                lib.load(dll_path)
            except Exception as e:
                raise Exception(f"Eroare la încărcarea driver-ului: {e}")
            cls._LIBS[key] = lib
        return lib

    @staticmethod
    def _tok_ident(pkcs11, slot):
        ti = pkcs11.getTokenInfo(slot)
        label = str(ti.label).strip()
        serial = str(ti.serialNumber).strip()
        return label, serial

    @staticmethod
    def list_all_certificates(dll_path):
        pkcs11 = HardwareTokenHSM._get_lib(dll_path)

        slots = pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            # poate driverul a rămas cu o stare veche -> o încercare cu reload
            pkcs11 = HardwareTokenHSM._get_lib(dll_path, force_reload=True)
            slots = pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            raise Exception("Nu s-a detectat niciun token USB conectat valid pentru acest driver!")

        certs_info = []
        for slot in slots:
            session = None
            try:
                label, serial = HardwareTokenHSM._tok_ident(pkcs11, slot)
                logging.info(f"Slot {slot}: token label='{label}', serial='{serial}'")

                session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)
                certs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])

                for cert in certs:
                    cka_id = session.getAttributeValue(cert, [PyKCS11.CKA_ID])[0]
                    cert_val = session.getAttributeValue(cert, [PyKCS11.CKA_VALUE])[0]
                    cert_bytes = bytes(cert_val)

                    try:
                        cert_obj = x509.load_der_x509_certificate(cert_bytes, default_backend())
                        cn = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                    except Exception:
                        cn = "Certificat Necunoscut"

                    certs_info.append({
                        'slot': slot,
                        'token_label': label,
                        'token_serial': serial,
                        'cka_id': tuple(cka_id),
                        'cn': cn,
                        'cert_der': cert_bytes
                    })
            except Exception as e:
                logging.warning(f"Eroare citire slot {slot}: {e}")
            finally:
                if session is not None:
                    try:
                        session.closeSession()
                    except Exception:
                        pass

        return certs_info

    @staticmethod
    def _resolve_slot(pkcs11, target_slot, token_serial, token_label):
        """Găsește slotul ACTUAL al token-ului (ID-ul se poate schimba)."""
        slots = pkcs11.getSlotList(tokenPresent=True)
        logging.info(f"Sloturi disponibile acum: {list(slots)} (slot memorat: {target_slot})")
        found = []
        for s in slots:
            try:
                label, serial = HardwareTokenHSM._tok_ident(pkcs11, s)
            except Exception as e:
                logging.warning(f"Nu pot citi token-ul din slotul {s}: {e}")
                continue
            found.append((s, label, serial))
            if token_serial and serial == token_serial and (not token_label or label == token_label):
                return s
        # fallback: doar serial
        for s, label, serial in found:
            if token_serial and serial == token_serial:
                return s
        # fallback: slotul memorat, dacă mai există
        if target_slot in slots:
            return target_slot
        # fallback: label
        for s, label, serial in found:
            if token_label and label == token_label:
                return s
        if len(slots) == 1:
            return slots[0]
        raise Exception(
            "Token-ul selectat nu mai este găsit (slot invalid). Sloturi văzute: "
            f"{found}. Apasă din nou pe CITEȘTE CERTIFICATE."
        )

    def _open_session(self, slot):
        # unele drivere (IDPlug) acceptă mai bine RW, altele doar RO -> încercăm ambele
        try:
            return self.pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        except PyKCS11.PyKCS11Error as e:
            logging.warning(f"openSession RW a eșuat ({e}); încerc sesiune read-only")
            return self.pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)

    def __init__(self, dll_path, pin, target_slot, target_cka_id, token_serial="", token_label="", cert_der=None):
        logging.info(f"--- INIȚIALIZARE HSM (slot memorat {target_slot}, serial '{token_serial}') ---")

        self.session = None
        self.pkcs11 = HardwareTokenHSM._get_lib(dll_path)

        try:
            slot = HardwareTokenHSM._resolve_slot(self.pkcs11, target_slot, token_serial, token_label)
        except Exception:
            # ultimă șansă: reîncărcăm driverul și reîncercăm
            logging.warning("Rezolvare slot eșuată, reîncarc driverul PKCS#11...")
            self.pkcs11 = HardwareTokenHSM._get_lib(dll_path, force_reload=True)
            slot = HardwareTokenHSM._resolve_slot(self.pkcs11, target_slot, token_serial, token_label)
        logging.info(f"Slot folosit pentru semnare: {slot}")

        try:
            self.session = self._open_session(slot)
        except PyKCS11.PyKCS11Error as e:
            if "SLOT_ID_INVALID" in str(e).upper() or "SLOT" in str(e).upper():
                logging.warning(f"Slot invalid ({e}); reîncarc driverul și reiau.")
                self.pkcs11 = HardwareTokenHSM._get_lib(dll_path, force_reload=True)
                slot = HardwareTokenHSM._resolve_slot(self.pkcs11, slot, token_serial, token_label)
                self.session = self._open_session(slot)
            else:
                raise

        try:
            self.session.login(pin)
            logging.info("Autentificare hardware reușită pe token-ul țintă!")
        except PyKCS11.PyKCS11Error as e:
            if "ALREADY_LOGGED_IN" in str(e).upper():
                logging.info("Utilizatorul era deja autentificat pe token.")
            else:
                self.logout()
                raise Exception(f"Autentificare eșuată! PIN greșit pentru token-ul ales? Detalii: {e}")

        # --- găsire certificat (după DER dacă îl avem, altfel după CKA_ID) ---
        cert_obj_handle = None
        all_certs = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
        for c in all_certs:
            try:
                val = bytes(self.session.getAttributeValue(c, [PyKCS11.CKA_VALUE])[0])
            except Exception:
                continue
            if cert_der is not None and val == cert_der:
                cert_obj_handle, self.cert_der = c, val
                break
        if cert_obj_handle is None and target_cka_id:
            for c in all_certs:
                cid = tuple(self.session.getAttributeValue(c, [PyKCS11.CKA_ID])[0])
                if cid == tuple(target_cka_id):
                    cert_obj_handle = c
                    self.cert_der = bytes(self.session.getAttributeValue(c, [PyKCS11.CKA_VALUE])[0])
                    break
        if cert_obj_handle is None:
            self.logout()
            raise Exception("Certificatul fizic nu a putut fi extras de pe token.")

        # --- găsire cheie privată (potrivită ca TIP cu certificatul: RSA sau EC) ---
        self.priv_key = None
        self.key_type = 'rsa'
        cert_pub = x509.load_der_x509_certificate(self.cert_der, default_backend()).public_key()
        want_ec = isinstance(cert_pub, _ec.EllipticCurvePublicKey)
        want_ck = PyKCS11.CKK_EC if want_ec else PyKCS11.CKK_RSA
        logging.info(f"Tip cheie publică în certificat: {'EC (ECDSA)' if want_ec else 'RSA'}")

        def _ktype(k):
            try:
                return self.session.getAttributeValue(k, [PyKCS11.CKA_KEY_TYPE])[0]
            except Exception:
                return None

        all_keys = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        logging.info("Chei private pe token: " + str([
            (tuple(self.session.getAttributeValue(k, [PyKCS11.CKA_ID])[0])[:4], _ktype(k)) for k in all_keys]))

        real_id = tuple(self.session.getAttributeValue(cert_obj_handle, [PyKCS11.CKA_ID])[0])
        cands = [k for k in all_keys if _ktype(k) == want_ck]
        # 1) același CKA_ID + același tip
        for k in cands:
            if real_id and tuple(self.session.getAttributeValue(k, [PyKCS11.CKA_ID])[0]) == real_id:
                self.priv_key = k
                break
        # 2) RSA: potrivire după modul
        if self.priv_key is None and not want_ec:
            n = cert_pub.public_numbers().n
            for k in cands:
                m = self.session.getAttributeValue(k, [PyKCS11.CKA_MODULUS])[0]
                if m and int.from_bytes(bytes(m), 'big') == n:
                    self.priv_key = k
                    break
        # 3) o singură cheie de tipul potrivit
        if self.priv_key is None and len(cands) == 1:
            self.priv_key = cands[0]

        if self.priv_key is None:
            self.logout()
            raise Exception("Cheia privată (de tipul certificatului) nu a putut fi găsită. "
                            "Posibil ca PIN-ul să fie pentru alt certificat.")

        self.key_type = 'ec' if want_ec else 'rsa'
        self.ec_size = ((cert_pub.curve.key_size + 7) // 8) if want_ec else 0
        logging.info(f"Cheie privată găsită, tip: {self.key_type}")

    def certificate(self):
        return self.cert_der, self.cert_der

    def sign(self, *args):
        try:
            if len(args) == 3:
                keyid, data, algo = args
            else:
                data, algo = args[0], args[1]

            logging.debug(f"Hardware token sign called. Algo={algo}, Data length={len(data)} bytes")

            if algo != 'sha256':
                raise Exception(f"Algoritm nesuportat: {algo}")

            if self.key_type == 'ec':
                raw = None
                try:
                    raw = bytes(self.session.sign(self.priv_key, data,
                                                  PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA256, None)))
                except PyKCS11.PyKCS11Error as e:
                    logging.warning(f"CKM_ECDSA_SHA256 indisponibil ({e}); semnez digest-ul cu CKM_ECDSA")
                    digest = hashlib.sha256(bytes(data)).digest()
                    raw = bytes(self.session.sign(self.priv_key, digest,
                                                  PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None)))
                h = len(raw) // 2
                return encode_dss_signature(int.from_bytes(raw[:h], 'big'), int.from_bytes(raw[h:], 'big'))

            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            sig = self.session.sign(self.priv_key, data, mech)
            return bytes(sig)
        except Exception as e:
            logging.error("Eroare la semnarea hardware", exc_info=True)
            raise e

    def logout(self):
        if self.session is None:
            return
        try:
            self.session.logout()
        except Exception:
            pass
        try:
            self.session.closeSession()
        except Exception:
            pass
        self.session = None


@dataclass
class SigningTask:
    pdf_path: str
    page_index: int
    box: Tuple[int, int, int, int]


class FileListWidget(tk.Frame):
    def __init__(self, parent, app, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.app = app
        
        self.canvas = tk.Canvas(self, bg="#1a1a2e", bd=0, highlightthickness=0, height=220)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#1a1a2e")
        
        self.scrollable_frame.bind("<Configure>", self._on_frame_configure)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.bind('<Configure>', self._on_canvas_configure)

        # mousewheel scrolling
        self.canvas.bind("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))
        self.canvas.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.items = []
        self.selected_idx = -1

    def _on_frame_configure(self, event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def _update_scroll(self):
        self.scrollable_frame.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def insert(self, idx, text):
        if idx == "end":
            idx = len(self.items)
            
        f = tk.Frame(self.scrollable_frame, bg="#1a1a2e")
        
        btn = tk.Button(f, text="🗑", bg="#1a1a2e", fg="#e94560", activebackground="#e94560", activeforeground="white", bd=0, cursor="hand2")
        btn.pack(side="right", padx=5)

        lbl = tk.Label(f, text=text, bg="#1a1a2e", fg="#eaeaea", anchor="w", cursor="hand2")
        lbl.pack(side="left", fill="x", expand=True, padx=5, pady=2)

        # mousewheel on each item row too
        for widget in (f, lbl, btn):
            widget.bind("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
            widget.bind("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))
            widget.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        
        self.items.insert(idx, {"frame": f, "label": lbl, "button": btn})
        self._repack()
        self.after(10, self._update_scroll)

    def _repack(self):
        for i, item in enumerate(self.items):
            item["frame"].pack_forget()
            item["frame"].pack(fill="x", pady=1)
            
            item["button"].config(command=lambda idx=i: self.app._delete_pdf(idx))
            
            def make_on_click(idx):
                def on_click(e):
                    self.select_idx(idx)
                    self.app._on_list_select(None)
                return on_click
                
            on_click_handler = make_on_click(i)
            item["label"].bind("<Button-1>", on_click_handler)
            item["frame"].bind("<Button-1>", on_click_handler)
            
            if i == self.selected_idx:
                item["frame"].config(bg="#e94560")
                item["label"].config(bg="#e94560")
            else:
                item["frame"].config(bg="#1a1a2e")
                item["label"].config(bg="#1a1a2e")

        self.after(10, self._update_scroll)

    def select_idx(self, idx):
        self.selected_idx = idx
        self._repack()

    def delete(self, idx, end=None):
        if idx == 0 and end == "end":
            for item in self.items:
                item["frame"].destroy()
            self.items.clear()
            self.selected_idx = -1
        else:
            if idx < len(self.items):
                self.items[idx]["frame"].destroy()
                self.items.pop(idx)
                if self.selected_idx == idx:
                    self.selected_idx = -1
                elif self.selected_idx > idx:
                    self.selected_idx -= 1
                self._repack()

    def curselection(self):
        return [self.selected_idx] if self.selected_idx != -1 else []
        
    def drop_target_register(self, dnd_type):
        self.canvas.drop_target_register(dnd_type)
        
    def dnd_bind(self, sequence, func):
        self.canvas.dnd_bind(sequence, func)


class PDFSignerApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("Semnătură Digitală PDF Pro")
        self.geometry("1300x850")
        self.configure(bg="#1a1a2e")

        self.pdf_paths, self.tasks = [], []
        self.current_idx = -1
        self.current_page = 0
        self.total_pages = 0
        
        self.pin_var = tk.StringVar()
        self.dll_combo_var = tk.StringVar(value=DEFAULT_DLL)
        self.progress_val = tk.DoubleVar(value=0.0)
        self.cert_mapping = {}
        
        self.settings = self._load_settings()
        self.dll_combo_var.set(self._initial_dll())
        self.dll_combo_var.trace_add("write", self._on_dll_changed)
        
        self._current_photoimg = None
        self._page_pdf_size = (595, 842)
        self._img_offset, self._img_scale = (0, 0), 1.0

        self._build_ui()
        self._style_widgets()
        logging.info("Aplicația UI a pornit cu succes.")

    def _load_settings(self):
        logging.info("Citire setări semnătură din fișier (sau inițializare cu default).")
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    loaded_settings = json.load(f)
                    logging.info(f"Setări încărcate cu succes: {loaded_settings}")
                    return {**DEFAULT_SETTINGS, **loaded_settings}
            except Exception as e:
                logging.error(f"Eroare la citirea JSON: {e}")
        return DEFAULT_SETTINGS.copy()

    def _save_settings(self, new_settings):
        logging.info(f"Salvare setări semnătură în fișier: {new_settings}")
        self.settings = {**self.settings, **new_settings}
        try:
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            logging.error(f"Eroare la salvarea JSON: {e}")

    def _initial_dll(self):
        """Alege driverul la pornire: ultimul folosit, altfel primul preset care există pe PC."""
        last = self.settings.get("last_dll", "")
        if last and os.path.exists(DLL_PRESETS.get(last, last)):
            return last
        for name, path in DLL_PRESETS.items():
            if os.path.exists(path):
                logging.info(f"Driver detectat automat: {name} -> {path}")
                return name
        return DEFAULT_DLL

    def _on_dll_changed(self, *args):
        """Reține driverul ales (preset sau cale manuală) pentru următoarea pornire."""
        val = self.dll_combo_var.get()
        if val and self.settings.get("last_dll") != val:
            self._save_settings({"last_dll": val})

    def _get_active_dll_path(self):
        """Preia calea DLL-ului fie din dicționarul de presetări, fie pe cea introdusă manual."""
        user_val = self.dll_combo_var.get()
        return DLL_PRESETS.get(user_val, user_val)

    def _browse_dll(self):
        """Permite utilizatorului să caute un fișier driver manual în calculator"""
        logging.info("Buton apăsat: _browse_dll (Căutare driver manual)")
        if IS_WINDOWS:
            filetypes = [("Fișiere DLL", "*.dll"), ("Toate fișierele", "*.*")]
        else:
            filetypes = [("PKCS#11 Driver Linux", "*.so *.so.*"), ("Toate fișierele", "*.*")]
        file = filedialog.askopenfilename(filetypes=filetypes)
        if file:
            logging.info(f"S-a selectat fișierul driver: {file}")
            self.dll_combo_var.set(file)

    def _build_ui(self):
        top = tk.Frame(self, bg="#0f3460", height=60)
        top.pack(fill="x")
        tk.Label(top, text="✦ SEMNĂTURĂ DIGITALĂ PDF PRO", font=("Segoe UI", 16, "bold"), bg="#0f3460", fg="#eaeaea").pack(side="left", padx=20)

        def open_support_link():
            logging.info("Buton apăsat: open_support_link (Susține proiectul)")
            import webbrowser
            webbrowser.open("https://buymeacoffee.com/ionutanton")

        btn_support = tk.Button(top, text="☕ Susține proiectul", command=open_support_link, bg="#e94560", fg="white", font=("Segoe UI", 10, "bold"), bd=0, padx=10, pady=5, cursor="hand2")
        btn_support.pack(side="right", padx=20)

        container = tk.Frame(self, bg="#1a1a2e")
        container.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(container, bg="#16213e", width=350)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="① DOCUMENTE PDF", font=("Segoe UI", 10, "bold"), bg="#16213e", fg="#e94560").pack(anchor="w", padx=15, pady=(10,0))
        f_btns = tk.Frame(self.sidebar, bg="#16213e")
        f_btns.pack(fill="x", padx=15, pady=5)
        tk.Button(f_btns, text="＋ ADAUGĂ", command=self._add_pdfs, bg="#e94560", fg="#eaeaea", bd=0).pack(side="left", expand=True, fill="x", padx=(0,2))
        tk.Button(f_btns, text="✕ GOLEȘTE", command=self._clear_all, bg="#0f3460", fg="#eaeaea", bd=0).pack(side="left", expand=True, fill="x")
        
        self.listb = FileListWidget(self.sidebar, self, bg="#1a1a2e")
        self.listb.pack(fill="x", padx=15, pady=5)
        
        try:
            self.listb.drop_target_register(DND_FILES)
            self.listb.dnd_bind('<<Drop>>', self._on_drop)
            self.sidebar.drop_target_register(DND_FILES)
            self.sidebar.dnd_bind('<<Drop>>', self._on_drop)
            self.drop_target_register(DND_FILES)
            self.dnd_bind('<<Drop>>', self._on_drop)
        except Exception as e:
            logging.error(f"Eroare la activarea drag and drop: {e}")

        tk.Button(self.sidebar, text="⚙ SETĂRI ASPECT SEMNĂTURĂ", command=self._open_settings_dialog, bg="#0f3460", fg="#4ade80", bd=0, pady=8, font=("Segoe UI", 9, "bold")).pack(fill="x", padx=15, pady=(10, 10))

        tk.Label(self.sidebar, text="② CONECTARE TOKEN USB", font=("Segoe UI", 10, "bold"), bg="#16213e", fg="#e94560").pack(anchor="w", padx=15, pady=(10,0))
        
        tk.Label(self.sidebar, text="Furnizor / Driver:" if IS_WINDOWS else "Furnizor / Driver (.so):", font=("Segoe UI", 8), bg="#16213e", fg="#8892a4").pack(anchor="w", padx=15, pady=(5,0))
        
        f_dll = tk.Frame(self.sidebar, bg="#16213e")
        f_dll.pack(fill="x", padx=15, pady=(0, 5))
        
        # OptionMenu (inlocuieste ttk.Combobox care cauzeaza segfault pe Ubuntu)
        self.dll_combo = tk.OptionMenu(f_dll, self.dll_combo_var, *list(DLL_PRESETS.keys()))
        self.dll_combo.config(bg="#1a1a2e", fg="#eaeaea", activebackground="#0f3460",
                              activeforeground="#eaeaea", highlightthickness=0, bd=0, anchor="w")
        self.dll_combo["menu"].config(bg="#1a1a2e", fg="#eaeaea")
        self.dll_combo.pack(side="left", fill="x", expand=True, padx=(0, 5))
        tk.Button(f_dll, text="📂", command=self._browse_dll, bg="#0f3460", fg="#eaeaea", bd=0, width=3, cursor="hand2").pack(side="right")

        f_action = tk.Frame(self.sidebar, bg="#16213e")
        f_action.pack(fill="x", padx=15, pady=(5,10))
        tk.Button(f_action, text="🔍 CITEȘTE CERTIFICATE (FĂRĂ PIN)", command=self._list_token_certs, bg="#0f3460", fg="#eaeaea", font=("Segoe UI", 8, "bold"), bd=0, pady=5, cursor="hand2").pack(fill="x")

        tk.Label(self.sidebar, text="Certificat Găsit:", font=("Segoe UI", 8, "bold"), bg="#16213e", fg="#eaeaea").pack(anchor="w", padx=15)
        self.cert_combo_var = tk.StringVar(value="")
        self.cert_combo = tk.OptionMenu(self.sidebar, self.cert_combo_var, "")
        self.cert_combo.config(bg="#1a1a2e", fg="#eaeaea", activebackground="#0f3460",
                               activeforeground="#eaeaea", highlightthickness=0, bd=0, anchor="w")
        self.cert_combo["menu"].config(bg="#1a1a2e", fg="#eaeaea")
        self.cert_combo.pack(fill="x", padx=15, pady=(0,10))

        tk.Label(self.sidebar, text="PIN Token:", font=("Segoe UI", 9, "bold"), bg="#16213e", fg="#eaeaea").pack(anchor="w", padx=15)
        self.pin_entry = tk.Entry(self.sidebar, textvariable=self.pin_var, show="*", bg="#1a1a2e", fg="#4ade80", bd=0, highlightthickness=1, font=("Segoe UI", 12))
        self.pin_entry.pack(fill="x", padx=15, pady=5)

        tk.Label(self.sidebar, text="Progress bar:", font=("Segoe UI", 9, "bold"), bg="#16213e", fg="#eaeaea").pack(anchor="w", padx=15)
        self.p_bar = ttk.Progressbar(self.sidebar, variable=self.progress_val, maximum=100)
        self.p_bar.pack(fill="x", padx=15, pady=(2, 20))
        self.btn_sign = tk.Button(self.sidebar, text="⚡ APLICĂ SEMNĂTURĂ BATCH", command=self._start_batch, font=("Segoe UI", 10, "bold"), bg="#e94560", fg="#eaeaea", bd=0, pady=15, cursor="hand2")
        self.btn_sign.pack(fill="x", padx=15)

        self.c_area = tk.Frame(container, bg="#1a1a2e")
        self.c_area.pack(side="left", fill="both", expand=True, padx=(0,10), pady=10)

        self.page_frame = tk.Frame(self.c_area, bg="#1a1a2e")
        self.page_frame.pack(fill="x", pady=(0, 5))
        
        tk.Button(self.page_frame, text="⏮ Prima", command=self._page_first, bg="#0f3460", fg="#eaeaea", bd=0, padx=5).pack(side="left", padx=2)
        tk.Button(self.page_frame, text="◀ Ant.", command=self._page_prev, bg="#0f3460", fg="#eaeaea", bd=0, padx=5).pack(side="left", padx=2)
        
        self.page_entry_var = tk.StringVar(value="1")
        self.page_entry = tk.Entry(self.page_frame, textvariable=self.page_entry_var, width=5, justify="center")
        self.page_entry.pack(side="left", padx=5)
        self.page_entry.bind("<Return>", self._page_goto)
        
        self.page_label = tk.Label(self.page_frame, text="/ 1", bg="#1a1a2e", fg="#eaeaea")
        self.page_label.pack(side="left", padx=(0, 5))

        tk.Button(self.page_frame, text="Urm. ▶", command=self._page_next, bg="#0f3460", fg="#eaeaea", bd=0, padx=5).pack(side="left", padx=2)
        tk.Button(self.page_frame, text="Ultima ⏭", command=self._page_last, bg="#0f3460", fg="#eaeaea", bd=0, padx=5).pack(side="left", padx=2)

        self.canvas = tk.Canvas(self.c_area, bg="#2d2d2d", bd=0, highlightthickness=0, cursor="crosshair")
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<ButtonPress-1>", self._on_mouse_press)
        self.canvas.bind("<B1-Motion>", self._on_mouse_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_mouse_release)
        
        self.canvas.bind("<MouseWheel>", self._on_mouse_wheel)
        self.canvas.bind("<Button-4>", self._on_mouse_wheel)
        self.canvas.bind("<Button-5>", self._on_mouse_wheel)

    def _on_mouse_wheel(self, event):
        if self.current_idx != -1:
            if event.num == 4 or event.delta > 0:
                self._page_prev()
            elif event.num == 5 or event.delta < 0:
                self._page_next()

    def _list_token_certs(self):
        logging.info("Buton apăsat: _list_token_certs (Căutare certificate pe token)")
        dll_path = self._get_active_dll_path()
        logging.info(f"Se caută certificate folosind driver-ul: {dll_path}")
        self.cert_combo_var.set("Caut pe porturile USB...")
        
        def fetch():
            try:
                certs = HardwareTokenHSM.list_all_certificates(dll_path)
                logging.info(f"S-au găsit {len(certs)} certificate pe token.")
                self.after(0, lambda: self._update_cert_dropdown(certs))
            except Exception as e:
                logging.error(f"Eroare apărută în timpul căutării token-ului: {e}", exc_info=True)
                self.after(0, lambda err=str(e): messagebox.showerror("Eroare Driver/Hardware", f"Verifică dacă driver-ul DLL/SO e corect și token-ul e în PC.\n\nDetalii: {err}"))
                self.after(0, lambda: self.cert_combo_var.set(""))

        threading.Thread(target=fetch, daemon=True).start()

    def _update_cert_dropdown(self, certs):
        self.cert_mapping.clear()
        menu = self.cert_combo["menu"]
        menu.delete(0, "end")
        if not certs:
            self.cert_combo_var.set("")
            messagebox.showwarning("Atenție", "Nu a fost găsit niciun certificat pe token-urile conectate.")
            return

        for c in certs:
            hex_id = bytes(c['cka_id']).hex()[:6].upper() or "noid"
            display_name = f"{c['cn']} ({c['token_label']}) [{hex_id}]"
            n = 2
            while display_name in self.cert_mapping:
                display_name = f"{c['cn']} ({c['token_label']}) [{hex_id}] #{n}"
                n += 1
            self.cert_mapping[display_name] = {'slot': c['slot'], 'cka_id': c['cka_id'],
                                                'token_serial': c.get('token_serial', ''),
                                                'token_label': c.get('token_label', ''),
                                                'cert_der': c.get('cert_der')}

        for name in self.cert_mapping.keys():
            menu.add_command(label=name, command=lambda v=name: self.cert_combo_var.set(v))
        self.cert_combo_var.set(list(self.cert_mapping.keys())[0])

    # --- GUI SETĂRI ASPECT ---
    def _open_settings_dialog(self):
        logging.info("Buton apăsat: _open_settings_dialog (Setări aspect semnătură)")
        diag = tk.Toplevel(self)
        diag.title("Personalizare Semnătură")
        diag.geometry("900x550")
        diag.configure(bg="#1a1a2e")
        diag.grab_set()
        
        diag._preview_logo = None

        v_contact = tk.StringVar(value=self.settings.get("contact", ""))
        v_location = tk.StringVar(value=self.settings.get("location", ""))
        v_reason = tk.StringVar(value=self.settings.get("reason", ""))
        v_border = tk.DoubleVar(value=float(self.settings.get("border", 0.5)))
        v_bg = tk.StringVar(value=self.settings.get("bg_color", "#ffffff"))
        v_out = tk.StringVar(value=self.settings.get("outline_color", "#000000"))
        v_transp = tk.BooleanVar(value=self.settings.get("transparent_bg", False))
        
        v_d_cn = tk.BooleanVar(value=self.settings.get("display_cn", True))
        v_d_date = tk.BooleanVar(value=self.settings.get("display_date", True))
        v_d_reason = tk.BooleanVar(value=self.settings.get("display_reason", True))
        v_d_loc = tk.BooleanVar(value=self.settings.get("display_location", False))
        v_d_cont = tk.BooleanVar(value=self.settings.get("display_contact", False))

        v_fontsize = tk.IntVar(value=self.settings.get("fontsize", 8))
        v_textalign = tk.StringVar(value=self.settings.get("textalign", "left"))
        v_linespacing = tk.DoubleVar(value=self.settings.get("linespacing", 1.2))
        
        v_lbl_cn = tk.StringVar(value=self.settings.get("lbl_cn", ""))
        v_lbl_date = tk.StringVar(value=self.settings.get("lbl_date", ""))
        v_lbl_reason = tk.StringVar(value=self.settings.get("lbl_reason", "Motiv:"))
        v_lbl_loc = tk.StringVar(value=self.settings.get("lbl_loc", ""))
        v_lbl_contact = tk.StringVar(value=self.settings.get("lbl_contact", ""))

        v_use_img = tk.BooleanVar(value=self.settings.get("use_image", False))
        v_img_path = tk.StringVar(value=self.settings.get("image_path", ""))

        def choose_color(var):
            logging.info("Buton apăsat: choose_color (Alege culoare)")
            color = colorchooser.askcolor(initialcolor=var.get(), title="Alege Culoare")
            if color[1]:
                logging.info(f"Culoare aleasă: {color[1]}")
                var.set(color[1])
            update_preview()

        def _safe_border():
            try:
                return max(0.0, float(v_border.get()))
            except Exception:
                return 0.5

        def save():
            logging.info("Buton apăsat: save (Salvează setări)")
            new_s = {
                "contact": v_contact.get(), "location": v_location.get(), "reason": v_reason.get(),
                "border": _safe_border(), "bg_color": v_bg.get(), "outline_color": v_out.get(), "transparent_bg": v_transp.get(),
                "display_cn": v_d_cn.get(), "display_date": v_d_date.get(), 
                "display_reason": v_d_reason.get(), "display_location": v_d_loc.get(), "display_contact": v_d_cont.get(),
                "fontsize": v_fontsize.get(), "textalign": v_textalign.get(), "linespacing": v_linespacing.get(),
                "lbl_cn": v_lbl_cn.get(), "lbl_date": v_lbl_date.get(), "lbl_reason": v_lbl_reason.get(),
                "lbl_loc": v_lbl_loc.get(), "lbl_contact": v_lbl_contact.get(),
                "use_image": v_use_img.get(), "image_path": v_img_path.get()
            }
            self._save_settings(new_s)
            diag.destroy()

        left_f = tk.Frame(diag, bg="#1a1a2e")
        left_f.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        notebook = ttk.Notebook(left_f)
        notebook.pack(fill="both", expand=True)

        t1 = tk.Frame(notebook, bg="#1a1a2e", padx=15, pady=15)
        notebook.add(t1, text="Date & Câmpuri")
        tk.Label(t1, text="Valorile Metadata:", font=("Segoe UI", 10, "bold"), bg="#1a1a2e", fg="#e94560").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,5))
        tk.Label(t1, text="Motiv (Reason):", bg="#1a1a2e", fg="#eaeaea").grid(row=1, column=0, sticky="w")
        tk.Entry(t1, textvariable=v_reason, width=30).grid(row=1, column=1, pady=2)
        tk.Label(t1, text="Locație (Location):", bg="#1a1a2e", fg="#eaeaea").grid(row=2, column=0, sticky="w")
        tk.Entry(t1, textvariable=v_location, width=30).grid(row=2, column=1, pady=2)
        tk.Label(t1, text="Contact:", bg="#1a1a2e", fg="#eaeaea").grid(row=3, column=0, sticky="w")
        tk.Entry(t1, textvariable=v_contact, width=30).grid(row=3, column=1, pady=2)

        tk.Label(t1, text="Elemente vizibile pe PDF:", font=("Segoe UI", 10, "bold"), bg="#1a1a2e", fg="#e94560").grid(row=4, column=0, columnspan=2, sticky="w", pady=(15,5))
        tk.Checkbutton(t1, text="Numele (CN)", variable=v_d_cn, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=5, column=0, sticky="w")
        tk.Checkbutton(t1, text="Data Semnării", variable=v_d_date, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=5, column=1, sticky="w")
        tk.Checkbutton(t1, text="Motivul", variable=v_d_reason, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=6, column=0, sticky="w")
        tk.Checkbutton(t1, text="Locația", variable=v_d_loc, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=6, column=1, sticky="w")
        tk.Checkbutton(t1, text="Contactul", variable=v_d_cont, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=7, column=0, sticky="w")

        t2 = tk.Frame(notebook, bg="#1a1a2e", padx=15, pady=15)
        notebook.add(t2, text="Aspect Vizual")
        tk.Label(t2, text="Culori și Contur:", font=("Segoe UI", 10, "bold"), bg="#1a1a2e", fg="#e94560").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,5))
        tk.Label(t2, text="Grosime chenar:", bg="#1a1a2e", fg="#eaeaea").grid(row=1, column=0, sticky="w")
        tk.Spinbox(t2, from_=0, to=5, increment=0.25, format="%.2f", textvariable=v_border, width=10).grid(row=1, column=1, sticky="w", pady=2)
        tk.Button(t2, text="🎨 Fundal", command=lambda: choose_color(v_bg), bg="#0f3460", fg="white", bd=0, width=15).grid(row=2, column=0, pady=5, sticky="w")
        tk.Button(t2, text="🎨 Text/Contur", command=lambda: choose_color(v_out), bg="#0f3460", fg="white", bd=0, width=15).grid(row=2, column=1, pady=5, sticky="w")

        tk.Checkbutton(t2, text="Fundal transparent (fără culoare)", variable=v_transp, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=6, column=0, columnspan=2, sticky="w", pady=(5,0))

        tk.Label(t2, text="Formatare Text:", font=("Segoe UI", 10, "bold"), bg="#1a1a2e", fg="#e94560").grid(row=3, column=0, columnspan=2, sticky="w", pady=(15,5))
        tk.Label(t2, text="Mărime Text (Font):", bg="#1a1a2e", fg="#eaeaea").grid(row=4, column=0, sticky="w")
        tk.Spinbox(t2, from_=4, to=36, textvariable=v_fontsize, width=10).grid(row=4, column=1, sticky="w", pady=2)
        tk.Label(t2, text="Aliniere Text:", bg="#1a1a2e", fg="#eaeaea").grid(row=5, column=0, sticky="w")
        cb_align = tk.OptionMenu(t2, v_textalign, "left", "center", "right")
        cb_align.config(bg="#1a1a2e", fg="#eaeaea", activebackground="#0f3460",
                        activeforeground="#eaeaea", highlightthickness=0, bd=0)
        cb_align["menu"].config(bg="#1a1a2e", fg="#eaeaea")
        cb_align.grid(row=5, column=1, sticky="w", pady=2)

        t3 = tk.Frame(notebook, bg="#1a1a2e", padx=15, pady=15)
        notebook.add(t3, text="Etichete (Prefixe)")
        tk.Label(t3, text="Lasă gol pentru a ascunde prefixul:", font=("Segoe UI", 9, "bold"), bg="#1a1a2e", fg="#e94560").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,10))
        tk.Label(t3, text="Prefix Nume (CN):", bg="#1a1a2e", fg="#eaeaea").grid(row=1, column=0, sticky="w")
        tk.Entry(t3, textvariable=v_lbl_cn, width=35).grid(row=1, column=1, pady=2)
        tk.Label(t3, text="Prefix Dată:", bg="#1a1a2e", fg="#eaeaea").grid(row=2, column=0, sticky="w")
        tk.Entry(t3, textvariable=v_lbl_date, width=35).grid(row=2, column=1, pady=2)
        tk.Label(t3, text="Prefix Motiv:", bg="#1a1a2e", fg="#eaeaea").grid(row=3, column=0, sticky="w")
        tk.Entry(t3, textvariable=v_lbl_reason, width=35).grid(row=3, column=1, pady=2)
        tk.Label(t3, text="Prefix Locație:", bg="#1a1a2e", fg="#eaeaea").grid(row=4, column=0, sticky="w")
        tk.Entry(t3, textvariable=v_lbl_loc, width=35).grid(row=4, column=1, pady=2)

        t4 = tk.Frame(notebook, bg="#1a1a2e", padx=15, pady=15)
        notebook.add(t4, text="Imagine / Logo")
        tk.Checkbutton(t4, text="Afișează o imagine în stânga (ex: Logo / Ștampilă)", variable=v_use_img, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").pack(anchor="w", pady=(0, 10))
        tk.Label(t4, text="Calea către imagine (PNG / JPG):", bg="#1a1a2e", fg="#eaeaea").pack(anchor="w")
        f_img = tk.Frame(t4, bg="#1a1a2e")
        f_img.pack(fill="x", pady=5)
        tk.Entry(f_img, textvariable=v_img_path).pack(side="left", fill="x", expand=True, padx=(0, 5))
        def browse_img():
            logging.info("Buton apăsat: browse_img (Alege imagine)")
            p = filedialog.askopenfilename(filetypes=[("Imagini", "*.png *.jpg *.jpeg")])
            if p:
                logging.info(f"Imagine selectată: {p}")
                v_img_path.set(p)
            update_preview()
        tk.Button(f_img, text="📂 Alege...", command=browse_img, bg="#0f3460", fg="white", bd=0, padx=10).pack(side="right")

        # PREVIEW
        right_f = tk.Frame(diag, bg="#16213e", padx=20, pady=20, width=350)
        right_f.pack(side="right", fill="y")
        tk.Label(right_f, text="PREVIZUALIZARE LIVE", font=("Segoe UI", 12, "bold"), bg="#16213e", fg="#eaeaea").pack(pady=(0,10))
        cvs_preview = tk.Canvas(right_f, width=350, height=200, bg="#dcdcdc", bd=0, highlightthickness=0)
        cvs_preview.pack(pady=10)
        tk.Button(right_f, text="💾 SALVEAZĂ SETĂRI", command=save, bg="#e94560", fg="white", font=("Segoe UI", 10, "bold"), bd=0, pady=15).pack(side="bottom", fill="x")

        def update_preview(*args):
            cvs_preview.delete("all")
            bg_c = v_bg.get()
            out_c = v_out.get()
            bw = _safe_border()
            f_size = v_fontsize.get()
            
            pad_out = 15
            box_w = 320
            box_h = 170
            cvs_preview.create_rectangle(pad_out, pad_out, pad_out + box_w, pad_out + box_h, fill=("" if v_transp.get() else bg_c), outline=out_c, width=bw)
            
            img_offset_x = 0
            if v_use_img.get() and os.path.exists(v_img_path.get()):
                try:
                    pil_img = Image.open(v_img_path.get())
                    ph = box_h - 10
                    pw = int(ph * (pil_img.width / pil_img.height))
                    pil_img = pil_img.resize((pw, ph), Image.LANCZOS)
                    diag._preview_logo = ImageTk.PhotoImage(pil_img)
                    cvs_preview.create_image(pad_out + 5, pad_out + 5, anchor="nw", image=diag._preview_logo)
                    img_offset_x = pw + 10 
                except: pass

            def cln(lbl):
                return lbl.strip() + " " if lbl.strip() else ""

            lines = []
            if v_d_cn.get(): lines.append(cln(v_lbl_cn.get()) + "NUME PRENUME TITULAR")
            if v_d_date.get(): lines.append(cln(v_lbl_date.get()) + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            if v_d_reason.get(): lines.append(cln(v_lbl_reason.get()) + v_reason.get())
            if v_d_loc.get(): lines.append(cln(v_lbl_loc.get()) + v_location.get())
            if v_d_cont.get(): lines.append(cln(v_lbl_contact.get()) + v_contact.get())
            
            text_str = "\n".join(lines)
            
            pad_left = pad_out + 5 + img_offset_x
            pad_right = pad_out + box_w - 5
            
            anchor_p = "nw"
            x_pos = pad_left
            if v_textalign.get() == "center":
                anchor_p = "n"
                x_pos = pad_left + (pad_right - pad_left) / 2
            elif v_textalign.get() == "right":
                anchor_p = "ne"
                x_pos = pad_right

            safe_size = min(max(f_size, 6), 24)
            cvs_preview.create_text(x_pos, pad_out + 10, anchor=anchor_p, text=text_str, fill=out_c, font=("Arial", safe_size), justify=v_textalign.get())

        for var in (v_reason, v_location, v_contact, v_border, v_bg, v_out, v_transp, v_d_cn, v_d_date, v_d_reason, v_d_loc, v_d_cont, v_fontsize, v_textalign, v_lbl_cn, v_lbl_date, v_lbl_reason, v_lbl_loc, v_lbl_contact, v_use_img, v_img_path):
            var.trace_add("write", update_preview)
            
        update_preview()

    # --- EXECUȚIE SEMNARE ---
    def _execute_sign(self, task: SigningTask, hsm: HardwareTokenHSM):
        logging.debug(f"Executing sign for PDF={task.pdf_path}, Page={task.page_index}, Box={task.box}")
        input_path = os.path.normpath(task.pdf_path)
        output_dir = os.path.join(os.path.dirname(input_path), "Semnate")
        if not os.path.exists(output_dir): 
            os.makedirs(output_dir)
        output_path = os.path.join(output_dir, f"{Path(input_path).stem}_semnat.pdf")

        ui_x1, ui_y1, ui_x2, ui_y2 = task.box
        
        temp_doc = fitz.open(input_path)
        temp_page = temp_doc.load_page(task.page_index)
        
        box_v = fitz.Rect(ui_x1, ui_y1, ui_x2, ui_y2)
        
        # 1. Calculăm geometria în SPAȚIUL VIZUAL (unde x/y merg perfect cu UI-ul)
        bg_r, bg_g, bg_b = hex_to_rgb(self.settings["bg_color"])
        out_r, out_g, out_b = hex_to_rgb(self.settings["outline_color"])
        bg_color = (bg_r, bg_g, bg_b)
        border_color = (out_r, out_g, out_b)
        
        img_offset_w = 0
        pad = 4
        img_rect_v = None
        if self.settings.get("use_image") and os.path.exists(self.settings.get("image_path")):
            img_rect_v = fitz.Rect(box_v.x0 + pad, box_v.y0 + pad, box_v.x0 + box_v.width / 2 - pad, box_v.y1 - pad)
            img_offset_w = box_v.width / 2

        text_rect_v = fitz.Rect(box_v.x0 + img_offset_w + 2, box_v.y0 + 2, box_v.x1 - 2, box_v.y1 - 2)

        # 2. Transformăm totul în SPAȚIUL UNROTATED (Neserotit) intern al PyMuPDF
        derot = temp_page.derotation_matrix
        rotation = temp_page.rotation
        
        border_rect = box_v * derot
        img_rect = img_rect_v * derot if img_rect_v else None
        text_rect = text_rect_v * derot

        # 3. Desenăm folosind parametrul rotate pentru a compensa rotația viewer-ului
        fill_c = None if self.settings.get("transparent_bg", False) else bg_color
        temp_page.draw_rect(border_rect, color=border_color, fill=fill_c, width=float(self.settings["border"]))
        
        if img_rect:
            try:
                temp_page.insert_image(img_rect, filename=self.settings["image_path"], keep_proportion=True, rotate=rotation)
            except Exception as e:
                logging.warning(f"Nu s-a putut procesa imaginea: {e}")

        fs = self.settings["fontsize"]
        align_str = self.settings["textalign"]
        align = fitz.TEXT_ALIGN_LEFT
        if align_str == "center":
            align = fitz.TEXT_ALIGN_CENTER
        elif align_str == "right":
            align = fitz.TEXT_ALIGN_RIGHT
            
        raw_date = datetime.datetime.now(datetime.timezone.utc).strftime("D:%Y%m%d%H%M%S+00'00'")
        viz_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cert_obj = x509.load_der_x509_certificate(hsm.cert_der, default_backend())
        try:
            cn_name = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except:
            cn_name = "Semnătură Necunoscută"

        def cln(lbl):
            return lbl.strip() + " " if lbl.strip() else ""

        lines = []
        if self.settings["display_cn"]: lines.append(cln(self.settings["lbl_cn"]) + cn_name)
        if self.settings["display_date"]: lines.append(cln(self.settings["lbl_date"]) + viz_date)
        if self.settings["display_reason"]: lines.append(cln(self.settings["lbl_reason"]) + self.settings["reason"])
        if self.settings["display_location"]: lines.append(cln(self.settings["lbl_loc"]) + self.settings["location"])
        if self.settings["display_contact"]: lines.append(cln(self.settings["lbl_contact"]) + self.settings["contact"])
        
        text_str = "\n".join(lines)
        
        # insert_textbox NU scrie nimic (și nu dă eroare) dacă textul nu încape în chenar -> micșorăm fontul până încape
        fs_try = float(fs)
        while True:
            rc = temp_page.insert_textbox(text_rect, text_str, fontsize=fs_try, color=border_color, align=align, rotate=rotation)
            if rc >= 0:
                if fs_try < fs:
                    logging.warning(f"Chenarul e prea mic pentru fontul {fs}; text scris cu fontul {fs_try}.")
                break
            fs_try -= 0.5
            if fs_try < 3:
                logging.error(f"Textul nu încape în chenar ({box_v.width:.0f}x{box_v.height:.0f}) nici cu font 3. "
                              "Desenează un chenar mai mare sau ascunde câmpuri.")
                break

        # Salvăm modificările vizuale în memorie
        datau = temp_doc.tobytes()
        
        # Calculăm poziția matematică a câmpului criptografic invizibil
        box_user = box_v * temp_page.derotation_matrix * (~temp_page.transformation_matrix)
        signaturebox = (box_user.x0, box_user.y0, box_user.x1, box_user.y1)
        temp_doc.close()

        # 2. GENERĂM SEMNĂTURA CRIPTOGRAFICĂ CU ASPECT INVIZIBIL
        dct = {
            "aligned": 0,
            "sigflags": 3,
            "sigflagsft": 132,
            "sigpage": task.page_index,
            "auto_sigfield": True,
            "signaturebox": signaturebox,
            "signform": False,
            "contact": self.settings["contact"],
            "location": self.settings["location"],
            "signingdate": raw_date,   
            "reason": self.settings["reason"],
            # Lăsăm endesive să facă doar widget-ul transparent, desenul real a fost făcut mai sus!
            "signature_manual": []
        }

        if getattr(hsm, 'key_type', 'rsa') == 'ec':
            dct['aligned'] = 8192  # ECDSA are lungime variabilă -> placeholder fix
        logging.debug(f"Signing dictionary (dct) parameters: {dct}")
        datas = cms.sign(datau, dct, None, cert_obj, (), 'sha256', hsm=hsm)
        logging.debug(f"Signature generated for {input_path}")

        with open(output_path, 'wb') as f:
            f.write(datau)
            f.write(datas)

    def _run_batch(self, pin, dll_path, target_slot, target_cka_id, token_serial='', token_label='', cert_der=None):
        logging.debug(f"Running batch sign. Total tasks: {len(self.tasks)}, DLL: {dll_path}, Slot: {target_slot}, CKA_ID: {target_cka_id}")
        total = len(self.tasks)
        hsm = None
        try:
            hsm = HardwareTokenHSM(dll_path, pin, target_slot, target_cka_id, token_serial, token_label, cert_der)
            
            errors = []
            for i, t in enumerate(self.tasks):
                try:
                    self._execute_sign(t, hsm)
                    self.after(0, lambda p=t.pdf_path: self._update_ui_list(p, "✓"))
                except Exception as e:
                    self.after(0, lambda p=t.pdf_path: self._update_ui_list(p, "✗"))
                    logging.error(f"Eroare fișier: {e}")
                    errors.append(f"{os.path.basename(t.pdf_path)}: {str(e)}")
                
                self.after(0, lambda p=((i+1)/total)*100: self.progress_val.set(p))
                
            if errors:
                err_msg = "Au apărut erori la semnarea următoarelor documente:\n\n" + "\n".join(errors)
                self.after(0, lambda msg=err_msg: messagebox.showwarning("Avertisment / Erori", msg))
            else:
                self.after(0, lambda: messagebox.showinfo("Gata", "Toate documentele au fost semnate cu succes!"))
            
        except Exception as e:
            logging.error(f"Eroare hardware la inițializare/semnare: {e}", exc_info=True)
            self.after(0, lambda err=str(e): messagebox.showerror("Eroare Hardware", err))
        finally:
            if hsm: 
                hsm.logout()
            self.after(0, lambda: self.btn_sign.config(state="normal"))

    def _start_batch(self):
        logging.info("Buton apăsat: _start_batch (Aplică semnătură batch)")
        if not self.tasks:
            messagebox.showwarning("Incomplet", "Adaugă PDF-uri și desenează chenarul de semnătură.")
            return
        
        selected_cert_name = self.cert_combo_var.get()
        if not selected_cert_name or not hasattr(self, 'cert_mapping') or selected_cert_name not in self.cert_mapping:
            messagebox.showwarning("Incomplet", "Te rog apasă pe CITEȘTE CERTIFICATE și alege cu ce vrei să semnezi.")
            return
            
        pin = self.pin_var.get()
        if not pin:
            messagebox.showwarning("Incomplet", "Introdu PIN-ul pentru certificatul selectat.")
            return

        target_cka_id = self.cert_mapping[selected_cert_name]['cka_id']
        target_slot = self.cert_mapping[selected_cert_name]['slot']
        token_serial = self.cert_mapping[selected_cert_name].get('token_serial', '')
        token_label = self.cert_mapping[selected_cert_name].get('token_label', '')
        cert_der = self.cert_mapping[selected_cert_name].get('cert_der')
        dll_path = self._get_active_dll_path()
            
        self.btn_sign.config(state="disabled")
        threading.Thread(target=self._run_batch, args=(pin, dll_path, target_slot, target_cka_id, token_serial, token_label, cert_der), daemon=True).start()

    def _update_page_controls(self):
        self.page_entry_var.set(str(self.current_page + 1))
        self.page_label.config(text=f"/ {self.total_pages}")

    def _page_first(self):
        logging.info("Buton apăsat: _page_first (Prima pagină)")
        if self.current_idx != -1: self._load_pdf_preview(self.current_idx, 0)

    def _page_prev(self):
        logging.info("Buton apăsat: _page_prev (Pagina anterioară)")
        if self.current_idx != -1 and self.current_page > 0: self._load_pdf_preview(self.current_idx, self.current_page - 1)

    def _page_next(self):
        logging.info("Buton apăsat: _page_next (Pagina următoare)")
        if self.current_idx != -1 and self.current_page < self.total_pages - 1: self._load_pdf_preview(self.current_idx, self.current_page + 1)

    def _page_last(self):
        logging.info("Buton apăsat: _page_last (Ultima pagină)")
        if self.current_idx != -1: self._load_pdf_preview(self.current_idx, self.total_pages - 1)

    def _page_goto(self, event=None):
        logging.info("Buton apăsat/Eveniment: _page_goto (Mergi la pagina specificată)")
        if self.current_idx != -1:
            try:
                p = int(self.page_entry_var.get()) - 1
                self._load_pdf_preview(self.current_idx, p)
            except ValueError:
                self._update_page_controls()

    def _load_pdf_preview(self, idx, page_num=0):
        self.current_idx = idx
        path = self.pdf_paths[idx]
        try:
            doc = fitz.open(path)
            self.total_pages = doc.page_count
            self.current_page = min(max(0, page_num), self.total_pages - 1)
            page = doc.load_page(self.current_page)
            self._page_pdf_size = (page.rect.width, page.rect.height)
            logging.debug(f"Loaded PDF preview: path={path}, page={self.current_page + 1}/{self.total_pages}, page_size={self._page_pdf_size}")
            pix = page.get_pixmap()
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
            self._img_scale = min(cw/img.width, ch/img.height, 1.0)
            nw, nh = int(img.width * self._img_scale), int(img.height * self._img_scale)
            img = img.resize((nw, nh), Image.LANCZOS)
            self._current_photoimg = ImageTk.PhotoImage(img)
            self._img_offset = ((cw-nw)//2, (ch-nh)//2)
            self.canvas.delete("all")
            self.canvas.create_image(self._img_offset[0], self._img_offset[1], anchor="nw", image=self._current_photoimg)
            doc.close()
            self._update_page_controls()
            
            for t in self.tasks:
                if t.pdf_path == path and t.page_index == self.current_page:
                    ox, oy, sc = self._img_offset[0], self._img_offset[1], self._img_scale
                    x1, y1, x2, y2 = t.box
                    cx1 = x1 * sc + ox
                    cy1 = y1 * sc + oy
                    cx2 = x2 * sc + ox
                    cy2 = y2 * sc + oy
                    self.canvas.create_rectangle(cx1, cy1, cx2, cy2, outline="#e94560", width=2, tags="sig_rect")
                    break
        except Exception as e:
            logging.error(f"Eroare _load_pdf_preview: {e}")

    def _delete_pdf(self, idx):
        logging.info(f"Buton apăsat: _delete_pdf (Șterge PDF de la indexul {idx})")
        if idx < 0 or idx >= len(self.pdf_paths): return
        path = self.pdf_paths[idx]
        logging.info(f"Se elimină fișierul: {path}")
        self.pdf_paths.pop(idx)
        self.tasks = [t for t in self.tasks if t.pdf_path != path]
        
        self.listb.delete(idx)
        
        if not self.pdf_paths:
            self._clear_all()
        else:
            if self.current_idx == idx:
                new_idx = min(idx, len(self.pdf_paths) - 1)
                self.listb.select_idx(new_idx)
                self._load_pdf_preview(new_idx)
            elif self.current_idx > idx:
                self.current_idx -= 1
                self._load_pdf_preview(self.current_idx)

    def _add_pdfs(self):
        logging.info("Buton apăsat: _add_pdfs (Adaugă documente PDF)")
        files = filedialog.askopenfilenames(filetypes=[("PDF", "*.pdf")])
        for f in files:
            logging.info(f"Fișier adăugat la listă: {f}")
            if f not in self.pdf_paths:
                self.pdf_paths.append(f); self.listb.insert("end", os.path.basename(f))
        if self.pdf_paths: self._load_pdf_preview(0)

    def _on_drop(self, event):
        files = self.tk.splitlist(event.data)
        added = False
        for f in files:
            if isinstance(f, bytes):
                try:
                    f = f.decode('utf-8')
                except UnicodeDecodeError:
                    if IS_WINDOWS:
                        f = f.decode('mbcs')
                    else:
                        f = f.decode('latin-1')
            if f.lower().endswith('.pdf'):
                if f not in self.pdf_paths:
                    self.pdf_paths.append(f)
                    self.listb.insert("end", os.path.basename(f))
                    added = True
        if added and self.current_idx == -1:
            self._load_pdf_preview(0)

    def _on_list_select(self, e):
        logging.info("Eveniment: _on_list_select (S-a selectat un fișier din listă)")
        sel = self.listb.curselection()
        if sel: 
            idx = sel[0]
            path = self.pdf_paths[idx]
            page_num = 0
            for t in self.tasks:
                if t.pdf_path == path:
                    page_num = t.page_index
                    break
            self._load_pdf_preview(idx, page_num)

    def _on_mouse_press(self, e): 
        self._drag_start = (e.x, e.y)
        self.canvas.delete("sig_rect")
        
    def _on_mouse_drag(self, e):
        if getattr(self, '_drag_start', None):
            self.canvas.delete("sig_rect")
            self.canvas.create_rectangle(self._drag_start[0], self._drag_start[1], e.x, e.y, outline="#e94560", width=2, tags="sig_rect")

    def _on_mouse_release(self, e):
        if getattr(self, '_drag_start', None) and self.current_idx != -1:
            logging.debug(f"Mouse released. Windows space rectangle: start=({self._drag_start[0]}, {self._drag_start[1]}), end=({e.x}, {e.y})")
            ox, oy, sc = self._img_offset[0], self._img_offset[1], self._img_scale
            pw, ph = self._page_pdf_size
            rx1, ry1 = (min(self._drag_start[0], e.x) - ox) / sc, (min(self._drag_start[1], e.y) - oy) / sc
            rx2, ry2 = (max(self._drag_start[0], e.x) - ox) / sc, (max(self._drag_start[1], e.y) - oy) / sc
            
            box = (int(rx1), int(ry1), int(rx2), int(ry2))
            logging.debug(f"Computed visual space rectangle: {box}")
            self._set_task(self.current_idx, box)
            self._drag_start = None

    def _set_task(self, idx, box):
        path = self.pdf_paths[idx]
        logging.info(f"Se setează chenarul vizual al semnăturii în UI pentru {path} pe pagina {self.current_page} la cutia {box}")
        for t in self.tasks:
            if t.pdf_path == path: 
                t.box = box
                t.page_index = self.current_page
                logging.info("Task de semnare actualizat pentru acest fișier.")
                return
        self.tasks.append(SigningTask(path, self.current_page, box))
        logging.info("Task de semnare nou creat pentru acest fișier.")

    def _update_ui_list(self, path, char):
        try:
            idx = self.pdf_paths.index(path)
            self.listb.delete(idx)
            self.listb.insert(idx, f"{char} {os.path.basename(path)}")
        except: pass

    def _clear_all(self):
        logging.info("Buton apăsat: _clear_all (Golește toate documentele)")
        self.pdf_paths, self.tasks = [], []
        self.listb.delete(0, "end")
        self.canvas.delete("all")
        self.cert_combo_var.set("")
        self.cert_combo["menu"].delete(0, "end")
        self.current_idx = -1
        self.current_page = 0
        self.total_pages = 0
        if hasattr(self, 'page_entry_var'):
            self.page_entry_var.set("1")
            self.page_label.config(text="/ 1")

    def _style_widgets(self):
        s = ttk.Style()
        s.theme_use("default")
        s.configure("TProgressbar", troughcolor="#1a1a2e", background="#e94560", thickness=12)

if __name__ == "__main__":
    app = PDFSignerApp()
    app.mainloop()
