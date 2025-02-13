rule Trojan_Win32_Fervis_A_2147593123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fervis.A"
        threat_id = "2147593123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fervis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 01 08 8a 51 01 41 84 d2 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = {53 41 40 42 43 83 e8 01 83 eb 01 83 e9 01 83 ea 01 5b e9}  //weight: 1, accuracy: High
        $x_1_3 = {8b 7c 24 40 33 f6 8a 04 3e 3c 61 7c 1e 3c 7a 7f 1a 8b e9 69 ed 01 04 00 00 0f be d0}  //weight: 1, accuracy: High
        $x_1_4 = "SetWindowTextA" ascii //weight: 1
        $x_1_5 = "GetSystemDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

