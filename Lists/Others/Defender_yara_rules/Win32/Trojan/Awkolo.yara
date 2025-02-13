rule Trojan_Win32_Awkolo_A_2147723894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Awkolo.A"
        threat_id = "2147723894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Awkolo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 00 00 00 80 8b 5d f0 8b 14 9d ?? ?? ?? ?? 43 89 d6 81 e6 fe ff ff 7f 09 ce 8b 4d f0 d1 ee 33 34 8d ?? ?? ?? ?? 83 e2 01 33 34 95 ?? ?? ?? ?? 89 34 85 ?? ?? ?? ?? be}  //weight: 1, accuracy: Low
        $x_1_2 = {49 6e 69 74 00 52 75 6e 00 77 65 62 66 61 6b 65 73 00 77 65 62 66 69 6c 74 65 72 73}  //weight: 1, accuracy: High
        $x_1_3 = {77 65 62 66 69 6c 74 65 72 73 00 73 65 74 5f 75 72 6c 00 64 61 74 61 5f 62 65 66 6f 72 65}  //weight: 1, accuracy: High
        $x_1_4 = {64 61 74 61 5f 69 6e 6a 65 63 74 [0-4] 64 61 74 61 5f 61 66 74 65 72 [0-4] 64 61 74 61 5f 65 6e 64}  //weight: 1, accuracy: Low
        $x_1_5 = {53 79 73 74 65 6d 00 50 61 6e 64 61 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c}  //weight: 1, accuracy: High
        $x_1_6 = "S:(ML;CIOI;NRNWNX;;;LW)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

