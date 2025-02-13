rule Trojan_Win32_Webprefix_A_2147642849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Webprefix.A"
        threat_id = "2147642849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Webprefix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 76 3d 25 64 2e 25 64 2e 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = "Softwareupdate|http://" ascii //weight: 1
        $x_1_3 = {8b 4d 0c bf 04 01 00 00 57 c7 45 ?? 3c 00 00 00 e8 ?? ?? ?? ?? 8b 4d 10 56 89 45 ?? 89 7d ?? e8 ?? ?? ?? ?? 89 45 ?? 8d 45 ?? 50 6a 00 6a 00 89 75 ?? ff 75 fc ff 15 ?? ?? ?? ?? 8b 4d 0c 6a ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Webprefix_B_2147644454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Webprefix.B"
        threat_id = "2147644454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Webprefix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".vplaycheck.com/go/" ascii //weight: 1
        $x_1_2 = "vplay-to.com" ascii //weight: 1
        $x_1_3 = "Softwareaktualisierung|http:" ascii //weight: 1
        $x_10_4 = {26 76 3d 25 64 2e 25 64 2e 25 64 00}  //weight: 10, accuracy: High
        $x_10_5 = {80 38 3b 75 02 88 18 41 3b ce 72 ed 57 8d 85 ?? ?? ff ff 50 6a 07 53 ff 75 10 ff 75 ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Webprefix_C_2147687100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Webprefix.C"
        threat_id = "2147687100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Webprefix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 6c 70 72 6f 74 65 63 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 6f 77 6e 6c 6f 61 64 20 50 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 31 3d 25 64 00 00 00 26 64 32 3d 25 64}  //weight: 1, accuracy: High
        $x_1_4 = {59 6a fd e9 75 ff ff ff 83 7d e0 00 74 06 ff 75 d8 ff}  //weight: 1, accuracy: High
        $x_1_5 = {59 33 f6 46 e9 50 fe ff ff 33 f6 e9 49 fe ff ff 55 8b ec 81 ec 10 01 00 00 53 56 57 33 db 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Webprefix_17709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Webprefix"
        threat_id = "17709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Webprefix"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 65 62 50 72 65 66 69 78 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_2 = "&os=%s&wpa=%s&ag=%s&um=%s" ascii //weight: 1
        $x_1_3 = "=steudf/ar" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows Media\\WMSDK\\General" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Webprefix_17709_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Webprefix"
        threat_id = "17709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Webprefix"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {31 68 70 3d 73 74 65 75 64 66 2f 61 72 00 00 00 25 30 38 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 00 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 57 65 62 50 72 65 66 69 78 00}  //weight: 4, accuracy: High
        $x_2_2 = "Offline Folder" ascii //weight: 2
        $x_2_3 = "&os=%s&wpa" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Webprefix_17709_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Webprefix"
        threat_id = "17709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Webprefix"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "1hp=steudf/ar" ascii //weight: 2
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\%s" ascii //weight: 1
        $x_5_4 = "WebPrefix" ascii //weight: 5
        $x_1_5 = "CLSID\\%s\\InprocServer32" ascii //weight: 1
        $x_2_6 = "Offline Folder" ascii //weight: 2
        $x_2_7 = "&os=%s&wpa" ascii //weight: 2
        $x_3_8 = "!ADWARE_SFX!" ascii //weight: 3
        $x_1_9 = "Enable Browser Extensions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

