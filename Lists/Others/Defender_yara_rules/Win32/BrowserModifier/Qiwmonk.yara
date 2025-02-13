rule BrowserModifier_Win32_Qiwmonk_224670_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Qiwmonk"
        threat_id = "224670"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Qiwmonk"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data.goosai.com" wide //weight: 1
        $x_1_2 = "@q.pieshua.com" wide //weight: 1
        $x_1_3 = "kxescore.exe" wide //weight: 1
        $x_1_4 = "baiduantray.exe" wide //weight: 1
        $x_1_5 = "HipsDaemon.exe" wide //weight: 1
        $x_1_6 = "HipsTray.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Qiwmonk_224670_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Qiwmonk"
        threat_id = "224670"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Qiwmonk"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 4e 74 75 52 4e 00 00 26 73 69 67 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 43 53 49 44 49 53 4b 00 00 00 00 78 78 76 6d 62 6f 78 78 78 68 61 72 64 64 69 73 6b 00 00 00 56 4d 77 61 72 65}  //weight: 1, accuracy: High
        $x_1_3 = {74 68 75 6e 64 65 72 28 33 37 38 39 37 29 2e 65 78 65 00 00 77 2b 62}  //weight: 1, accuracy: High
        $x_1_4 = {64 6f 77 6e 7e 5c 00 00 5c 00 00 00 67 73 78 7a 7e 5c 00 00 66 69 6c 65 6e 61 6d 65 3d 00 00 00 74 65 6d 70 64 6f 77 6e}  //weight: 1, accuracy: High
        $x_1_5 = "&appid=%s&sid=%" ascii //weight: 1
        $x_1_6 = "&in_cpu=%s&in_mac=%s&in_disk=%s&ver=" ascii //weight: 1
        $x_1_7 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 48 6f 6d 65 50 61 67 65}  //weight: 1, accuracy: High
        $x_1_8 = "\\StartMenu\\Internet Expleror.lnk" wide //weight: 1
        $x_1_9 = {5c 00 49 00 45 00 81 67 1f 90 4f 6d c8 89 68 56 2e 00 6c 00 6e 00 6b}  //weight: 1, accuracy: High
        $x_1_10 = "ver=2.0&soft=%s%c=%s&in_disk=%s" ascii //weight: 1
        $x_1_11 = {00 64 65 73 63 72 5f 64 6f 77 6e 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 26 64 65 73 63 72 5f 61 64 75 72 6c 3d 22 00}  //weight: 1, accuracy: High
        $x_1_13 = {51 00 4a 00 57 00 4d 00 4f 00 4e 00 4b 00 45 00 59 00 4d 00 55 00 54 00 45 00 58 00 5f 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {63 00 64 00 6e 00 2e 00 62 00 61 00 69 00 7a 00 68 00 75 00 2e 00 63 00 63 00 2f 00 79 00 6f 00 75 00 78 00 69 00 2f 00 69 00 6e 00 64 00 65 00 78 00 5f 00 25 00 64 00 2e 00 68 00 74 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_15 = {73 26 73 69 c7 45 ?? 64 3d 25 73 c7 45 ?? 26 76 65 72}  //weight: 1, accuracy: Low
        $x_1_16 = {61 00 6e 00 c7 45 ?? 67 00 59 00 c7 45 ?? 75 00 2e 00}  //weight: 1, accuracy: Low
        $x_1_17 = "%02X-%02X-%02X-%s&ver=2.0&soft=%" ascii //weight: 1
        $x_1_18 = {26 74 67 25 64 3d 25 64 00 00 00 00 25 73 3a 25 64 7c 00 00 26 76 65 72 3d 00 00 00 49 6e 73 74 61 6c 6c 44 61 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

