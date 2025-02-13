rule Trojan_Win64_TwoDash_B_2147926520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TwoDash.B!dha"
        threat_id = "2147926520"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TwoDash"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {69 c9 fd 43 03 00 48 8d 52 03 81 c1 c3 9e 26 00 8b c1 69 c9 fd 43 03 00 c1 e8 18 30 42 fc 81 c1 c3 9e 26 00 8b c1 69 c9 fd 43 03 00 c1 e8 18 30 42 fd 81 c1 c3 9e 26 00 8b c1 c1 e8 18 30 42 fe 49 83 e8 01 75 ba}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

