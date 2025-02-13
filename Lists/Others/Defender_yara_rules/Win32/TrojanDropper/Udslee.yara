rule TrojanDropper_Win32_Udslee_A_2147634497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Udslee.gen!A"
        threat_id = "2147634497"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Udslee"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c7 45 e4 cd fc f8 26 68 61 1d 00 00 e8}  //weight: 3, accuracy: High
        $x_3_2 = {c7 45 e4 d1 08 2e 55 68 ef 1b 00 00 e8}  //weight: 3, accuracy: High
        $x_3_3 = {c7 45 e4 cd fc a1 8b 68 6e 1b 00 00 e8}  //weight: 3, accuracy: High
        $x_3_4 = {c7 45 e4 d1 08 2e 59 68 9b 20 00 00 e8}  //weight: 3, accuracy: High
        $x_1_5 = {70 64 5b 64 76 5d 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 64 72 76 49 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {76 62 69 66 75 65 6b 7a 6e 6d 40 67 6a 69 74 6b 00}  //weight: 1, accuracy: High
        $x_1_8 = {69 65 72 75 68 64 73 6c 6c 65 6f 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

