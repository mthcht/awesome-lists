rule TrojanProxy_Win32_Hioles_A_2147646323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Hioles.A"
        threat_id = "2147646323"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hioles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 10 ff 75 0c ff d7 3b c6 7e ?? 39 75 14 74 15 8b 4d 10 8b 09 81 f9 47 45 54 20 74 ?? 81 f9 50 4f 53 54 74 ?? 56 50 ff 75 10 ff 75 08 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 16 50 ff 74 24 14 c7 00 ?? ?? ?? ?? c7 40 04 ?? ?? ?? ?? c6 40 08 ?? ff 15 ?? ?? ?? ?? 83 f8 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Hioles_B_2147652996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Hioles.B"
        threat_id = "2147652996"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hioles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 10 8b 09 81 f9 47 45 54 20 74 ?? 81 f9 50 4f 53 54 74 ?? 56 50 ff 75 10 ff 75 08 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {50 ff 74 24 14 c7 00 85 b2 04 77 c7 40 04 ce 38 e0 33 c6 40 08 04 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

