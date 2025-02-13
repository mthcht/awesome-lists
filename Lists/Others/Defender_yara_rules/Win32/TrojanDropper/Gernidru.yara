rule TrojanDropper_Win32_Gernidru_A_2147608249_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gernidru.gen!A"
        threat_id = "2147608249"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gernidru"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4e 49 47 45 52 53 48 45 4c 4c 33 32 2e 44 4c 4c 00}  //weight: 2, accuracy: High
        $x_1_2 = {c0 4c 08 ff 04}  //weight: 1, accuracy: High
        $x_1_3 = {80 74 01 ff 98}  //weight: 1, accuracy: High
        $x_1_4 = {ff 74 24 04 ff 53 dc}  //weight: 1, accuracy: High
        $x_1_5 = {ff 53 e4 5e [0-16] ff 53 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

