rule Trojan_Win32_Kilim_A_2147681703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.A"
        threat_id = "2147681703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFile, %web%/%kimlikfile%" ascii //weight: 1
        $x_1_2 = "FileCreateDir, %sDrive%\\Windows\\AdobeFlash" ascii //weight: 1
        $x_1_3 = "app appid=\"%kimlik%" ascii //weight: 1
        $x_1_4 = "Run, %sDrive%\\Windows\\AdobeFlash\\%A_ScriptName%" ascii //weight: 1
        $x_1_5 = "DllCall(ShellExecute, uint, 0, str, \"RunAs\"," ascii //weight: 1
        $x_1_6 = "&Window Spy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Kilim_B_2147682103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.B"
        threat_id = "2147682103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 45 78 74 65 6e 73 69 6f 6e 49 6e 73 74 61 6c 6c 46 6f 72 63 65 6c 69 73 74 2c 20 31 2c [0-45] 2e 78 6d 6c 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 2c 20 45 6e 61 62 6c 65 4c 55 41 2c 20 30 0d}  //weight: 2, accuracy: High
        $x_1_3 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 2c 20 [0-15] 46 6c 61 73 68 55 70 64 61 74 65}  //weight: 1, accuracy: Low
        $x_1_4 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 2c 20 [0-15] 46 6c 61 73 68 55 70 64 61 74 65}  //weight: 1, accuracy: Low
        $x_1_5 = {53 74 72 69 6e 67 54 72 69 6d 52 69 67 68 74 2c [0-15] 2c 20 [0-15] 2c 20 34 0d 0a}  //weight: 1, accuracy: Low
        $x_2_6 = {4b 43 4a 43 48 48 43 58 48 4b 4a 5f 43 2c 20 2d 31 0d 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kilim_A_2147682199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.gen!A"
        threat_id = "2147682199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%id%;%direXX%\\setup.xml" ascii //weight: 1
        $x_1_2 = "%direXX%\\FlashPlayer.exe" ascii //weight: 1
        $x_1_3 = "%direXX%\\%king%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kilim_C_2147682449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.C"
        threat_id = "2147682449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%windir%\\FlashTopia\\FlashMedia.exe" ascii //weight: 1
        $x_1_2 = "web:=@#(\"234FB2FF69CE584301D591DD5EE6413917730A4C15F2\")," ascii //weight: 1
        $x_1_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 25 77 65 62 25 2f 25 [0-8] 25 2c 20 25 41 5f 54 65 6d 70 25 5c}  //weight: 1, accuracy: Low
        $x_1_4 = "IfInString, A_ScriptDir, FlashTopia" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Kilim_B_2147684199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.gen!B"
        threat_id = "2147684199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%A_AppData%\\install_flash.exe" ascii //weight: 1
        $x_1_2 = "DllCall(ShellExecute, uint, 0, str, \"RunAs\"" ascii //weight: 1
        $x_1_3 = "%A_Appdata%\\flash.xpi" ascii //weight: 1
        $x_1_4 = "RegExReplace(YandexPref, \"\\\\\\\\Twains" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Kilim_D_2147684666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.D"
        threat_id = "2147684666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%A_Temp%\\ChromePref.txt" ascii //weight: 1
        $x_1_2 = "%A_Temp%\\YandexPref.txt" ascii //weight: 1
        $x_1_3 = "%A_Temp%\\OperaPref.txt" ascii //weight: 1
        $x_1_4 = {30 30 30 72 61 73 67 65 6c 65 6b 6c 61 73 6f 72 30 30 30 [0-3] 25 72 61 73 67 65 6c 65 6b 6c 61 73 6f 72 25}  //weight: 1, accuracy: Low
        $x_1_5 = "%A_AppData%\\install_browser.exe" ascii //weight: 1
        $x_1_6 = "RegExReplace(ChromePref, \"\\\\\\\\" ascii //weight: 1
        $x_1_7 = "(opera = 1)" ascii //weight: 1
        $x_1_8 = "Twains_64" ascii //weight: 1
        $x_1_9 = {2f 63 72 78 [0-3] 2e 7a 69 70 00}  //weight: 1, accuracy: Low
        $x_1_10 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-49] 25 72 65 67 70 61 74 68 25}  //weight: 1, accuracy: Low
        $x_1_11 = {5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d [0-3] 45 6e 61 62 6c 65 4c 55 41 [0-3] 30}  //weight: 1, accuracy: Low
        $x_1_12 = "\"shell32\\ShellExecute\", uint, 0, str, \"RunAs\"" ascii //weight: 1
        $x_1_13 = "%A_Appdata%\\flash.xpi" ascii //weight: 1
        $x_1_14 = {2b 53 48 00 25 41 5f 41 70 70 44 61 74 61 25 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_Kilim_E_2147684667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.E"
        threat_id = "2147684667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%A_Temp%\\ChromePref.txt" ascii //weight: 1
        $x_1_2 = "%A_Temp%\\YandexPref.txt" ascii //weight: 1
        $x_1_3 = "%A_Temp%\\OperaPref.txt" ascii //weight: 1
        $x_1_4 = {30 30 30 72 61 73 67 65 6c 65 6b 6c 61 73 6f 72 30 30 30 00 25 72 61 73 67 65 6c 65 6b 6c 61 73 6f 72 25}  //weight: 1, accuracy: High
        $x_1_5 = "%A_AppData%\\install_browser.exe" ascii //weight: 1
        $x_1_6 = "RegExReplace(ChromePref, \"\\\\\\\\\" . Prefix ." ascii //weight: 1
        $x_1_7 = "(opera = 1)" ascii //weight: 1
        $x_1_8 = {54 77 61 69 6e 73 5f 36 34 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kilim_G_2147684897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.G"
        threat_id = "2147684897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "110"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "/background.js" ascii //weight: 50
        $x_50_2 = "/Preferences" ascii //weight: 50
        $x_50_3 = {65 00 6b 00 6c 00 65 00 6e 00 74 00 69 00 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 50, accuracy: Low
        $x_50_4 = {65 6b 6c 65 6e 74 69 2f [0-16] 2e 65 78 65}  //weight: 50, accuracy: Low
        $x_10_5 = {5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 10, accuracy: High
        $x_10_6 = {67 75 6e 63 65 6c 6c 65 6d 65 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_5_7 = {46 6c 61 73 68 [0-1] 50 6c 61 79 65 72}  //weight: 5, accuracy: Low
        $x_5_8 = {63 68 72 6f 6d 65 2e 65 78 65 00 [0-15] 62 72 6f 77 73 65 72 2e 65 78 65}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 2 of ($x_5_*))) or
            ((2 of ($x_50_*) and 1 of ($x_10_*))) or
            ((3 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kilim_G_2147684897_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.G"
        threat_id = "2147684897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 43 00 72 00 78 00 [0-4] 2f 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 00 43 00 72 00 78 00 [0-4] 2f 00 6d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 2e 00 6a 00 73 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\Preferences" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kilim_G_2147684897_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.G"
        threat_id = "2147684897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "background.js" wide //weight: 1
        $x_1_2 = "regsvr32.exe /s zlib.dll" wide //weight: 1
        $x_1_3 = "taskkill.exe /f /t /im chrome.exe" wide //weight: 1
        $x_1_4 = {79 00 6f 00 6c 00 2b 00 72 00 61 00 6e 00 64 00 6f 00 6d 00 ?? ?? ?? ?? ?? ?? ?? ?? 72 00 61 00 6e 00 64 00 6f 00 6d 00 2d 00 6b 00 65 00 79 00}  //weight: 1, accuracy: Low
        $x_1_5 = "\"devtools://\") < 0)" ascii //weight: 1
        $x_1_6 = {75 72 6c 73 3a 20 5b ?? 2a 3a 2f 2f 2a 2f 2a ?? 5d}  //weight: 1, accuracy: Low
        $x_1_7 = "\\Users\\Eren\\" wide //weight: 1
        $x_1_8 = "5C 50 72 65 66 65 72 65 6E 63 65 73 4E 65 77" wide //weight: 1
        $x_1_9 = "5C 47 6F 6F 67 6C 65 5C 43 68 72 6F 6D 65 5C 55 73 65 72" wide //weight: 1
        $x_1_10 = "\\Applets\\Regedit" wide //weight: 1
        $x_1_11 = "\\u0130lk kullan\\u0131c" ascii //weight: 1
        $x_1_12 = "\"path\": \"yol+random\"," ascii //weight: 1
        $x_1_13 = {2e 70 68 70 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 3b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 74 74 70 2e 73 65 6e 64 28 29 3b}  //weight: 1, accuracy: Low
        $x_1_14 = "\"name\": \"Guvenlik Duvari\"," ascii //weight: 1
        $x_1_15 = {72 67 6c 65 72 69 73 69 6c 00}  //weight: 1, accuracy: High
        $x_1_16 = "5c 41 70 70 6c 65 74 73 5c 52 65 67 65 64 69 74" wide //weight: 1
        $x_1_17 = "5c 6d 61 6e 69 66 65 73 74 2e 6a 73 6f 6e" wide //weight: 1
        $x_1_18 = {22 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00 00 00 06 00 00 00 47 00 45 00 54 00}  //weight: 1, accuracy: High
        $x_1_19 = {25 00 69 00 64 00 25 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 25 00 6b 00 65 00 79 00 25 00 ?? ?? ?? ?? ?? ?? 25 00 70 00 61 00 74 00 68 00 25 00}  //weight: 1, accuracy: Low
        $x_1_20 = {69 64 6b 65 79 00 00 00 6d 61 6e 69 66 65 73 74 78 00 00 00 70 72 65 66 65 72 65 6e 63 65 73 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Kilim_H_2147685155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.H"
        threat_id = "2147685155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "molotofcu.com/my.txt" ascii //weight: 2
        $x_2_2 = "profonixuser.net/profonix.txt" ascii //weight: 2
        $x_2_3 = {53 6d 61 72 74 20 50 6c 61 79 65 72 20 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 0a 4e 61 6d 65 5f 53 74 61 72 74 20 3d 20 6e 65 74 75 70 64 61 74 65 41 64 62}  //weight: 2, accuracy: High
        $x_2_4 = "pp=7b0d0a20202022657874656e73696f6e73223a207b0d0a2020202020202273657474696e6773" ascii //weight: 2
        $x_2_5 = {64 6f 44 65 6c 65 74 65 55 70 64 61 74 65 3a 0a 7b 0a 50 72 6f 63 65 73 73 2c 20 43 6c 6f 73 65 2c 20 47 6f 6f 67 6c 65 55 70 64 61 74 65 2e 65 78 65 0a 46 69 6c 65 44 65 6c 65 74 65 2c}  //weight: 2, accuracy: High
        $x_1_6 = "645772697465222c2022636f6e74656e7453657474" ascii //weight: 1
        $x_1_7 = "sosyalmedyakusu.com" ascii //weight: 1
        $x_1_8 = "%A_Temp%\\xupdate.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kilim_I_2147685191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.I"
        threat_id = "2147685191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "30303072617367656c656b6c61736f72303030" ascii //weight: 10
        $x_1_2 = "22636c6970626f61726452656164222c2022636c6970626f6172645772697465222c2022636f6e74656e745365747469" ascii //weight: 1
        $x_1_3 = "74696d65223a20223133303138363638363935383638303338222c" ascii //weight: 1
        $x_1_4 = "AppData%\\Smart Player Installer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kilim_L_2147685219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.L"
        threat_id = "2147685219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://crxupdate.pw/Crxx/update.txt" wide //weight: 1
        $x_1_2 = "http://crxupdate.pw/Crxx/background.js" wide //weight: 1
        $x_1_3 = "http://crxupdate.pw/Crxx/flash.xpi" wide //weight: 1
        $x_1_4 = "cryware@outlook.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kilim_J_2147686345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.J"
        threat_id = "2147686345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "scriptable_host\": [ \"http://*/*\" ]" ascii //weight: 1
        $x_1_2 = {61 70 69 22 3a 20 5b [0-64] 22 63 6c 69 70 62 6f 61 72 64 57 72 69 74 65}  //weight: 1, accuracy: Low
        $x_1_3 = "//Google//Chrome//User Data//Default//Preferences" ascii //weight: 1
        $x_1_4 = {63 68 72 6f 6d 65 2e 65 78 65 00 [0-8] 6f 70 65 72 61 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "\\winregist.er" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Kilim_K_2147687174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.K"
        threat_id = "2147687174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 32 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 30 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 31 8d 85}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 32 51 ff d6 8d 95 b0 fe ff ff 6a 30 52 ff d6 8d 85 90 fe ff ff 6a 31 50 ff d6}  //weight: 1, accuracy: High
        $x_1_3 = "\\Users\\CRYPT\\Desktop\\" wide //weight: 1
        $x_1_4 = {4f 00 70 00 65 00 6e 00 00 00 00 00 53 00 65 00 6e 00 64 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 54 00 65 00 78 00 74 00 00 00 00 00 53 00 74 00 61 00 74 00 75 00 73 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "\\Yandex\\YandexBrowser\\User Data\\Default" wide //weight: 1
        $x_1_7 = "\\Opera Software\\Opera Stable" wide //weight: 1
        $x_1_8 = {52 00 75 00 6e 00 00 00 40 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {44 65 63 72 79 70 74 42 79 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Kilim_C_2147691364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.gen!C"
        threat_id = "2147691364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "%A_AppData%\\chromium.exe" ascii //weight: 100
        $x_1_2 = "taskkill /IM GoogleUpdate.exe /F" ascii //weight: 1
        $x_1_3 = "taskkill /IM opera_autoupdate.exe /F" ascii //weight: 1
        $x_1_4 = "taskkill /IM yupdate-exec.exe /F" ascii //weight: 1
        $x_1_5 = "schtasks /Delete /TN GoogleUpdateTaskMachineCore /F" ascii //weight: 1
        $x_1_6 = "schtasks /Delete /TN GoogleUpdateTaskMachineUA /F" ascii //weight: 1
        $x_1_7 = "taskkill /IM chrome.exe /F" ascii //weight: 1
        $x_1_8 = "taskkill /IM browser.exe /F" ascii //weight: 1
        $x_1_9 = "taskkill /IM opera.exe /F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kilim_P_2147691383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.P"
        threat_id = "2147691383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 22 68 74 74 70 3a 2f 2f 77 68 6f 73 2e 61 6d 75 6e 67 2e 75 73 2f 70 69 6e 67 6a 73 2f 3f 6b 3d [0-15] 2c 20 22 70 69 6e 67 6a 73 2e 6a 73 22}  //weight: 1, accuracy: Low
        $x_1_2 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 [0-8] 5f 4c 69 6e 6b 2c 20 22 (62 67|63) 2e 74 78 74 22 2c 20 33 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_3 = "taskkill /IM chrome.exe /F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kilim_T_2147693068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.T"
        threat_id = "2147693068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 22 68 74 74 70 3a 2f 2f 77 68 6f 73 2e 61 6d 75 6e 67 2e 75 73 2f 70 69 6e 67 6a 73 2f 3f 6b 3d [0-15] 2c 20 22 70 69 6e 67 6a 73 2e 6a 73 22}  //weight: 3, accuracy: Low
        $x_3_2 = "taskkill /IM chrome.exe /F" ascii //weight: 3
        $x_1_3 = "%cikan_site%/Civan_Coder/background.js" ascii //weight: 1
        $x_1_4 = "//%cikan_site%/sky_coder/sky.js" ascii //weight: 1
        $x_1_5 = "wget.exe -O \"%A_AppData%\\arsiv.exe\" \"%Php_Link%arsiv_link\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kilim_D_2147693089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.gen!D"
        threat_id = "2147693089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetDownload(\"http://www.filmverme.com" ascii //weight: 2
        $x_1_2 = "%domain%/ahk/req.php?type=" ascii //weight: 1
        $x_2_3 = "schtasks /Delete /TN GoogleUpdateTaskMachineCore /F" ascii //weight: 2
        $x_1_4 = "schtasks /Delete /TN GoogleUpdateTaskMachineUA /F" ascii //weight: 1
        $x_1_5 = "taskkill /IM chrome.exe /F" ascii //weight: 1
        $x_1_6 = "taskkill /IM browser.exe /F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kilim_U_2147694448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.U"
        threat_id = "2147694448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /Delete /TN GoogleUpdateTaskMachineCore /F" ascii //weight: 1
        $x_1_2 = "schtasks /Delete /TN GoogleUpdateTaskMachineUA /F" ascii //weight: 1
        $x_1_3 = "taskkill /IM chrome.exe /F" ascii //weight: 1
        $x_1_4 = "taskkill /IM browser.exe /F" ascii //weight: 1
        $x_1_5 = "wget.exe -O \"%A_AppData%\\arsiv.exe\" \"%Php_Link%arsiv_link\"" ascii //weight: 1
        $x_1_6 = "&Window Spy" wide //weight: 1
        $x_1_7 = "GetDownload(Php_Link . \"js\", \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kilim_V_2147694449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.V"
        threat_id = "2147694449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "GetDownload(Site_Link, Path, 240, 500)" ascii //weight: 2
        $x_2_2 = "taskkill /IM chrome.exe /F" ascii //weight: 2
        $x_2_3 = "taskkill /IM browser.exe /F" ascii //weight: 2
        $x_2_4 = "taskkill /IM opera.exe /F" ascii //weight: 2
        $x_1_5 = "%cikan_site%/Civan_Coder/background.js" ascii //weight: 1
        $x_1_6 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 22 68 74 74 70 3a 2f 2f 77 68 6f 73 2e 61 6d 75 6e 67 2e 75 73 2f 70 69 6e 67 6a 73 2f 3f 6b 3d [0-15] 2c 20 22 70 69 6e 67 6a 73 2e 6a 73 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kilim_W_2147695176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.W"
        threat_id = "2147695176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks /Delete /TN GoogleUpdateTaskMachineCore /F" ascii //weight: 1
        $x_1_2 = "schtasks /Delete /TN GoogleUpdateTaskMachineUA /F" ascii //weight: 1
        $x_1_3 = "taskkill /IM chrome.exe /F" ascii //weight: 1
        $x_1_4 = "taskkill /IM browser.exe /F" ascii //weight: 1
        $x_1_5 = "sky_coder_win_exe" ascii //weight: 1
        $x_1_6 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 22 68 74 74 70 3a 2f 2f [0-16] 2f 79 65 6e 69 2e 65 78 65 22 2c 20 22 79 65 6e 69 2e 65 78 65 22 2c 20 31 2c 20 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kilim_AB_2147697618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.AB"
        threat_id = "2147697618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 61 62 6c 65 4c 55 41 00 00 00 43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e [0-6] 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 63 68 72 6f 6d 65}  //weight: 1, accuracy: Low
        $x_1_3 = {41 75 74 6f 55 70 64 61 74 65 43 68 65 63 6b 50 65 72 69 6f 64 4d 69 6e 75 74 65 73 [0-8] 44 69 73 61 62 6c 65 41 75 74 6f 55 70 64 61 74 65 43 68 65 63 6b 73 43 68 65 63 6b 62 6f 78 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_4 = ".xyz/exe/default_apps/" ascii //weight: 1
        $x_1_5 = "\\drive.crx" ascii //weight: 1
        $x_1_6 = "\\external_extensions.json" ascii //weight: 1
        $x_1_7 = "\\Secure Preferences" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kilim_AB_2147697618_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.AB"
        threat_id = "2147697618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 61 62 6c 65 4c 55 41 00 00 00 43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "goo.gl/dkDgt9" ascii //weight: 1
        $x_1_3 = "--load-component-extension=\"" ascii //weight: 1
        $x_1_4 = {00 4a 53 00 00 5c 62 61 63 6b 67 72 6f 75 6e 64 2e 6a 73}  //weight: 1, accuracy: High
        $x_1_5 = {00 5c 6a 71 75 65 72 79 2e 6d 69 6e 2e 6a 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 63 68 72 6f 6d 69 75 6d 2e 65 78 65 00 00 00 5c 63 68 72 6f 6d 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_7 = {41 75 74 6f 55 70 64 61 74 65 43 68 65 63 6b 50 65 72 69 6f 64 4d 69 6e 75 74 65 73 [0-8] 44 69 73 61 62 6c 65 41 75 74 6f 55 70 64 61 74 65 43 68 65 63 6b 73 43 68 65 63 6b 62 6f 78 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_8 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e [0-6] 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 63 68 72 6f 6d 65}  //weight: 1, accuracy: Low
        $x_1_9 = {23 31 31 34 00 00 00 00 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 63 68 72 6f 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Kilim_AC_2147717057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilim.AC!bit"
        threat_id = "2147717057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 4d 77 61 72 65 00 56 69 72 74 75 61 6c 42 6f 78}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_3 = {63 68 72 6f 6d 65 2e 65 78 65 00 [0-8] 6f 70 65 72 61 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "//Google//Chrome//User Data//Default//Preferences" ascii //weight: 1
        $x_1_5 = {66 65 69 64 6f 77 6e 73 2e 63 6f 6d 2f [0-32] 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

