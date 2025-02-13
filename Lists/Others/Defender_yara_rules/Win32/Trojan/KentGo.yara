rule Trojan_Win32_KentGo_18139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KentGo"
        threat_id = "18139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KentGo"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 70 72 69 70 00 00 00 2e 69 6e 66 00 00 00 00 6c 62 6b 00 5c 69 6e 66 5c 69 70 00 2e 64 61 74}  //weight: 2, accuracy: High
        $x_2_2 = {5c 6c 69 70 72 69 70 2e 64 6c 6c 00 5c 66 73 75 74 6b 2e 64 6c 6c 00 00 52 65 6d 6f 74 65 20 49 50 52 49 50 20 53 65 72 76 69 63 65 00 00 00 00 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73}  //weight: 2, accuracy: High
        $x_2_3 = "Listener reads Remote Routing Information Protocol (RIP) packets" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KentGo_18139_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KentGo"
        threat_id = "18139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KentGo"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {4e 49 50 52 50 2e 44 4c 4c 00 53 65 72 76 69 63 65 48 61 6e 64 6c 65 72 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 3, accuracy: High
        $x_2_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Ext\\Settings\\{DC888631-57F5-4AF4-86B3-BDE5F854DCBF}\\" ascii //weight: 2
        $x_2_3 = "Classes\\CLSID\\{0E5CBF21-D15F-11d0-8301-00AA005B4383}\\InProcServer32\\" ascii //weight: 2
        $x_3_4 = "WS\\inf\\optkec.inf" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KentGo_18139_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KentGo"
        threat_id = "18139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KentGo"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 61 69 64 75 2e 63 6f 6d 2f 73 3f 77 64 3d 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6e 2f 73 65 61 72 63 68 3f 68 6c 3d 7a 68 2d 43 4e 26 71 3d 00 68 74 74 70 3a 2f 2f 73 65 61 72 63 68 2e 63 6e 2e 79 61 68 6f 6f 2e 63 6f 6d 2f 73 65 61 72 63 68 3f 70 3d 00 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 73 6f 67 6f 75 2e 63 6f 6d 2f 77 65 62 3f 73 6f 67 6f 75 68 6f 6d 65 3d 26 73 68 75 72 75 3d 73 68 6f 75 26 71 75 65 72 79 3d 00 00 00 68 74 74 70 3a 2f 2f 73 6f 2e 31 36 33 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 70 68 70 3f 71 3d 00}  //weight: 3, accuracy: High
        $x_3_2 = {2e 43 48 49 00 [0-15] 5c 48 65 6c 70 5c ?? ?? 00}  //weight: 3, accuracy: Low
        $x_1_3 = "CVER%#" ascii //weight: 1
        $x_1_4 = "RNNM%#" ascii //weight: 1
        $x_1_5 = "DWNM%#" ascii //weight: 1
        $x_1_6 = "RTNM%#" ascii //weight: 1
        $x_1_7 = "BDUD%#" ascii //weight: 1
        $x_1_8 = "COKB%#" ascii //weight: 1
        $x_1_9 = "RNTM%#" ascii //weight: 1
        $x_1_10 = "SBD%#" ascii //weight: 1
        $x_3_11 = "http://dw.mtsou.com/" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((3 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

