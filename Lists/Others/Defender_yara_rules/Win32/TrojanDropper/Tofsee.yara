rule TrojanDropper_Win32_Tofsee_A_2147610828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tofsee.gen!A"
        threat_id = "2147610828"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c7 03 74 1a e8 ?? ?? 00 00 33 d2 6a 19 59 f7 f1 80 c2 61 88 94}  //weight: 2, accuracy: Low
        $x_2_2 = {37 38 2e 31 30 39 2e 31 36 2e 32 35 30 00}  //weight: 2, accuracy: High
        $x_1_3 = {6e 65 74 73 66 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_4 = {6e 65 74 73 66 5f 6d 2e 69 6e 66 0d 0a}  //weight: 1, accuracy: High
        $x_1_5 = {5c 5c 2e 5c 50 61 73 73 54 68 72 75 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 5c 00 2e 00 5c 00 72 00 6f 00 74 00 63 00 65 00 74 00 6f 00 72 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

