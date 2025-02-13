rule TrojanDropper_Win32_Fedripto_A_2147650232_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Fedripto.A"
        threat_id = "2147650232"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Fedripto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 30 74 05 80 c1 ?? eb 03 80 c1 ?? 88 0c 30 8b 4c 24 10 40 3b c1 72 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {46 64 72 31 33 38 69 70 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

