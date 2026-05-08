#  LAB 17 — Cracker OWASP UnCrackable Android Level 3

> **Cours : Sécurité des applications mobiles**  
> **Difficulté : Avancé**  
> **Outils : Android Studio · apktool · jadx-GUI · Ghidra · Python 3**

---

## 🎯 Objectifs d'apprentissage

À la fin de ce writeup, tu sauras :

- Décompiler et patcher une APK (smali + Java)
- Analyser une librairie native `.so` avec Ghidra
- Contourner l'anti-debug, anti-Frida, anti-root et vérification d'intégrité
- Comprendre un XOR byte par byte et calculer le mot de passe secret
- Tout ça avec **uniquement des outils gratuits**

---

## 🛠️ Prérequis & Outils

| Outil | Usage | Lien |
|-------|-------|------|
| Android Studio | Émulateur Pixel 5 (sans Google Play) | https://developer.android.com/studio |
| jadx-GUI | Décompilation Java | https://github.com/skylot/jadx/releases |
| apktool | Décompilation/recompilation APK | https://apktool.org/docs/install |
| Ghidra | Analyse de librairies natives | https://ghidra-sre.org |
| Python 3 | Script de décodage XOR | https://python.org |
| ADB | Communication avec l'émulateur | Inclus dans Android Studio |

### Télécharger l'APK

```powershell
# Windows / PowerShell
Invoke-WebRequest -Uri "https://github.com/OWASP/owasp-mstg/raw/master/Crackmes/Android/Level_03/UnCrackable-Level3.apk" -OutFile "UnCrackable-Level3.apk"

# Vérifier l'émulateur
adb devices

# Installer l'APK
adb install UnCrackable-Level3.apk
```

---

## Étape 1 — Analyse statique avec jadx-GUI

### Lancement

Ouvrir jadx-GUI → **File → Open file** → sélectionner `UnCrackable-Level3.apk`

Naviguer vers : `sg.vantagepoint.uncrackable3 → MainActivity`

### Ce qu'on découvre dans MainActivity.java

```java
// La clé XOR est visible en clair !
private static final String xorkey = "pizzapizzapizzapizzapizz";

// Les protections dans onCreate()
protected void onCreate(Bundle bundle) {
    verifyLibs();           // vérifie le CRC de libfoo.so et classes.dex
    init(xorkey.getBytes()); // envoie la clé XOR à la librairie native

    // Thread anti-debugger
    new AsyncTask<Void, String, String>() {
        public String doInBackground(Void... voidArr) {
            while (!Debug.isDebuggerConnected()) {
                SystemClock.sleep(100L);
            }
            return null;
        }
        public void onPostExecute(String str) {
            MainActivity.this.showDialog("Debugger detected!");
            System.exit(0);
        }
    }.execute(null, null, null);

    // Détections root + tamper
    if (RootDetection.checkRoot1() || RootDetection.checkRoot2() || 
        RootDetection.checkRoot3() || IntegrityCheck.isDebuggable(...) || 
        tampered != 0) {
        showDialog("Rooting or tampering detected.");
    }
}

// La vérification du mot de passe est déléguée au natif
public void verify(View view) {
    String string = ((EditText) findViewById(...)).getText().toString();
    if (this.check.check_code(string)) {
        // "Success!"
    }
}
```

 **Observation clé** : La vraie vérification du mot de passe est dans `libfoo.so`, pas en Java. La clé XOR `pizzapizzapizzapizzapizz` est envoyée à la librairie native via `init()`.

### Premier lancement — comportement attendu


> <img width="493" height="723" alt="1" src="https://github.com/user-attachments/assets/da9c0f00-b1e6-4d38-86b6-c54c9ef1fa99" />

L'app détecte l'émulateur rooté et se ferme immédiatement.

---

##  Étape 2 — Décompiler l'APK avec apktool

```powershell
# Télécharger apktool (Windows)
Invoke-WebRequest -Uri "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar" -OutFile "apktool.jar"

# Décompiler
java -jar apktool.jar d UnCrackable-Level3.apk -o uncrackable3
```

### Structure obtenue

```
uncrackable3/
├── smali/
│   └── sg/vantagepoint/uncrackable3/
│       ├── MainActivity.smali      ← à modifier
│       ├── MainActivity$2.smali    ← thread anti-debugger
│       └── CodeCheck.smali
├── lib/
│   ├── arm64-v8a/libfoo.so
│   ├── armeabi-v7a/libfoo.so
│   ├── x86/libfoo.so
│   └── x86_64/libfoo.so           ← celui qu'on va patcher
└── AndroidManifest.xml
```

---

##  Étape 3 — Patch smali (neutraliser les détections)

Ouvrir `uncrackable3/smali/sg/vantagepoint/uncrackable3/MainActivity.smali` dans VS Code.

### Patch 1 — Neutraliser showDialog()

Faire **Ctrl+F** → chercher `showDialog` → premier résultat (la méthode elle-même).

**Avant :**
```smali
.method private showDialog(Ljava/lang/String;)V
    .locals 3
    .line 38
    new-instance v0, Landroid/app/AlertDialog$Builder;
    ... (tout le code du popup)
.end method
```

**Après :**
```smali
.method private showDialog(Ljava/lang/String;)V
    .locals 3
    return-void
.end method
```

### Patch 2 — Contourner la détection root/tamper dans onCreate()

Faire **Ctrl+F** → `showDialog` → troisième résultat (dans `onCreate`).

**Avant :**
```smali
:cond_0
const-string v0, "Rooting or tampering detected."
.line 127
invoke-direct {p0, v0}, Lsg/vantagepoint/uncrackable3/MainActivity;->showDialog(Ljava/lang/String;)V

.line 130
:cond_1
new-instance v0, Lsg/vantagepoint/uncrackable3/CodeCheck;
```

**Après :**
```smali
:cond_0
goto :cond_1

.line 130
:cond_1
new-instance v0, Lsg/vantagepoint/uncrackable3/CodeCheck;
```

> ⚠️**Important** : Utiliser `goto :cond_1` et non `return-void` — sinon `super.onCreate()` n'est jamais appelé et l'app crashe avec `SuperNotCalledException`.

### Recompiler, signer et installer

```powershell
# Recompiler
java -jar apktool.jar b uncrackable3 -o UnCrackable-Level3-patched.apk

# Créer un keystore de debug
& "C:\Program Files\Java\jdk-25\bin\keytool.exe" -genkey -v `
  -keystore my-debug.keystore -alias androiddebugkey `
  -keyalg RSA -keysize 2048 -validity 10000 `
  -storepass android -keypass android `
  -dname "CN=Android Debug,O=Android,C=US"

# Signer
& "$env:LOCALAPPDATA\Android\Sdk\build-tools\36.1.0\apksigner.bat" sign `
  --ks "my-debug.keystore" `
  --ks-pass pass:android --key-pass pass:android `
  UnCrackable-Level3-patched.apk

# Installer
adb uninstall owasp.mstg.uncrackable3
adb install UnCrackable-Level3-patched.apk
```



<img width="635" height="824" alt="2" src="https://github.com/user-attachments/assets/b2da3d2b-fb4c-4cb8-b112-78d1516b86f4" />
 L'app s'ouvre sans popup — les détections Java sont contournées !

---

## Étape 4 — Patch de libfoo.so avec Ghidra (anti-debug + anti-Frida)

Malgré le patch smali, l'app crashait encore à cause de `libfoo.so` qui contient une fonction exécutée **avant même `onCreate()`**.

### Analyser libfoo.so dans Ghidra

1. Lancer Ghidra → **New Project** → Non-Shared → nom `lab17`
2. **File → Import File** → `uncrackable3/lib/x86_64/libfoo.so`
3. Double-clic → **Analyze → Yes**

### Identifier la fonction malveillante

Dans **Program Tree → .init_array** → double-clic sur `_INIT_0`

<img width="1568" height="729" alt="3" src="https://github.com/user-attachments/assets/0b876da9-60d8-4784-92ae-aa8e760bbc76" />


Le décompilateur révèle :

```c
void _INIT_0(void) {
    pthread_create(&local_10, 0x0, FUN_001037c0, 0x0); // ← thread anti-Frida
    // ... initialisation de variables
    DAT_0010705c = DAT_0010705c + 1; // ← compteur CRITIQUE (doit valoir 2)
    return;
}
```

`FUN_001037c0` est le thread qui :
- Ouvre `/proc/self/maps` en boucle
- Cherche les strings `"frida"` et `"xposed"`
- Si trouvé → appelle `goodbye()` qui tue l'app

### Comprendre le compteur DAT_0010705c

Dans `Java_sg_vantagepoint_uncrackable3_CodeCheck_bar` (vérification du mot de passe) :

```c
if (DAT_0010705c == 2) {   // doit valoir EXACTEMENT 2 !
    FUN_001012c0(local_48);
    // ... comparaison avec le mot de passe
}
```

`DAT_0010705c` est incrémenté par :
- `_INIT_0` au chargement de la lib (+1)
- `init()` appelé depuis Java avec la clé pizza (+1)

→ Total attendu = **2**. Si on met `RET` au début de `_INIT_0`, le compteur reste à 1 et la vérification ne s'exécute jamais !

### La solution — patcher avec Python

Au lieu de patcher dans Ghidra (compliqué pour les multi-bytes), on patch directement le binaire :

```python
# patch_libfoo.py
with open('apk_extracted/lib/x86_64/libfoo.so', 'rb') as f:
    data = bytearray(f.read())

# Remplacer CALL pthread_create (e8 49 d4 ff ff) par 5x NOP (90 90 90 90 90)
# Adresse 0x1038c2 dans le fichier
data[0x38c2] = 0x90
data[0x38c3] = 0x90
data[0x38c4] = 0x90
data[0x38c5] = 0x90
data[0x38c6] = 0x90

with open('libfoo_v2.so', 'wb') as f:
    f.write(data)
print('Patch OK!')
```

```powershell
python patch_libfoo.py

# Copier dans tous les dossiers
copy "libfoo_v2.so" "uncrackable3\lib\x86_64\libfoo.so"
copy "libfoo_v2.so" "uncrackable3\lib\x86\libfoo.so"
copy "libfoo_v2.so" "uncrackable3\lib\arm64-v8a\libfoo.so"
copy "libfoo_v2.so" "uncrackable3\lib\armeabi-v7a\libfoo.so"
```

Recompiler, signer et réinstaller (mêmes commandes qu'à l'étape 3).

---

## 🧩 Étape 5 — Analyser la logique de vérification dans libfoo.so

### La fonction check_code

Dans Ghidra → Symbol Tree → `Java_sg_vantagepoint_uncrackable3_CodeCheck_bar`

```c
undefined * Java_sg_vantagepoint_uncrackable3_CodeCheck_bar(...) {
    byte local_48[40];  // buffer de 24 bytes

    if (DAT_0010705c == 2) {
        FUN_001012c0(local_48);  // remplit local_48 avec la clé dérivée

        // Récupère l'input utilisateur
        lVar2 = GetStringUTFChars(param_1, param_3, 0);
        iVar1 = GetStringUTFLength(param_1, param_3);

        if (iVar1 == 0x18) {  // longueur exacte = 24 caractères
            uVar4 = 0;
            do {
                // Comparaison XOR octet par octet
                if (input[uVar4]   != DAT_00107040[uVar4]   ^ local_48[uVar4]  ) goto FAIL;
                if (input[uVar4+1] != DAT_00107041[uVar4]   ^ local_48[uVar4+1]) goto FAIL;
                if (input[uVar4+2] != DAT_00107042[uVar4]   ^ local_48[uVar4+2]) goto FAIL;
                uVar4 += 3;
            } while (uVar4 < 0x18);
            return SUCCESS;
        }
    }
FAIL:
    return NULL;
}
```

`DAT_00107040` = la clé `pizza` (copiée là par `init()`)  
`local_48` = les bytes calculés par `FUN_001012c0`

Donc : **mot de passe = pizza XOR local_48**

### La fonction obfusquée FUN_001012c0

Cette fonction contient ~90 `malloc()` et une liste chaînée — c'est de l'obfuscation Tigress/O-LLVM pour masquer la logique utile.

<!-- IMAGE: screenshot Ghidra montrant la fonction obfusquée avec les malloc -->

**La donnée utile est à la toute fin de la fonction :**

```c
// Lignes 1515-1517 — les 24 bytes encodés (little-endian)
*param_1   = 0x1549170f1311081d;
param_1[1] = 0x15131d5a1903000d;
param_1[2] = 0x14130817005a0e08;
```

---

## Étape 6 — Décoder le mot de passe avec Python

```python
# decode_key.py
import struct

# Les 3 qwords extraits de FUN_001012c0 (little-endian)
q1 = 0x1549170f1311081d
q2 = 0x15131d5a1903000d
q3 = 0x14130817005a0e08

# Convertir en bytes (little-endian)
encoded = struct.pack('<QQQ', q1, q2, q3)
print("Encoded bytes:", encoded.hex())
# → 1d0811130f1749150d0003195a1d1315080e5a0017081314

# XOR avec la clé pizza (24 caractères)
xor_key = b"pizzapizzapizzapizzapizz"
secret = bytes(a ^ b for a, b in zip(encoded, xor_key))
print("Clé secrète :", secret.decode())
# → making owasp great again
```

```powershell
python decode_key.py
# Clé secrète : making owasp great again
```
<img width="726" height="285" alt="image" src="https://github.com/user-attachments/assets/7ed37fab-03ab-43e5-8728-49d73e977da4" />

---

##  Résultat final

```powershell
adb shell input text "making owasp great again"
# Puis cliquer VERIFY dans l'app
```

<img width="595" height="711" alt="image" src="https://github.com/user-attachments/assets/ad9ea915-e650-43f6-b8fc-4a767012da4d" />


** `making owasp great again` — Challenge résolu !**

---

## Récapitulatif des protections et des patches

| Protection | Technique | Patch appliqué |
|-----------|-----------|----------------|
| Détection root | `checkRoot1/2/3()` en Java | `goto :cond_1` dans smali |
| Vérification intégrité | CRC de `libfoo.so` et `classes.dex` | `goto :cond_1` dans smali |
| Anti-debug Java | `AsyncTask` + `Debug.isDebuggerConnected()` | Contourné par `goto` |
| Anti-Frida natif | Thread qui scanne `/proc/self/maps` | 5x `NOP` sur `pthread_create` |
| Obfuscation native | ~90 `malloc()` + liste chaînée LCG | Analyse statique → fin de fonction |
| Clé XOR | Stockée en little-endian dans le binaire | Script Python de décodage |

---

## Leçons de sécurité

1. **Ne jamais stocker de clés en clair** — même obfusquées, elles sont récupérables statiquement
2. **Les protections natives sont contournables** — `_INIT_array` est visible dans Ghidra
3. **L'obfuscation ralentit mais n'empêche pas** — la donnée utile est toujours là, à la fin de la fonction
4. **Le compteur d'état est un point faible** — `DAT_0010705c == 2` est une condition binaire patchable
5. **Toujours vérifier l'architecture** — x86_64 pour l'émulateur, arm64 pour un vrai device

---

## Structure du repo

```
lab17/
├── README.md                          ← ce fichier
├── UnCrackable-Level3.apk             ← APK original
├── UnCrackable-Level3-patched.apk     ← APK patché final
├── uncrackable3/                      ← dossier décompilé par apktool
│   ├── smali/sg/vantagepoint/uncrackable3/
│   │   └── MainActivity.smali        ← patché (goto :cond_1)
│   └── lib/x86_64/libfoo.so          ← patché (NOP sur pthread_create)
├── patch_libfoo.py                    ← script de patch binaire
└── decode_key.py                      ← script de décodage XOR
```

---

## 🔗 Ressources

- [OWASP Mobile Security Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/)
- [OWASP UnCrackable Apps](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes)
- [Ghidra Documentation](https://ghidra-sre.org/)
- [apktool Documentation](https://apktool.org/)
- [Android Smali/Baksmali](https://github.com/JesusFreke/smali)
