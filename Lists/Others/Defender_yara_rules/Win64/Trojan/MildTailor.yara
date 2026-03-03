rule Trojan_Win64_MildTailor_A_2147964014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MildTailor.A!dha"
        threat_id = "2147964014"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MildTailor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c7 41 8b 54 85 00 0f b7 04 41 49 03 d6 45 8b 1c 84 4d 03 de 80 7a 01 77}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 41 f7 f3 32 d3 41 3a d0 74 ?? 44 32 c2 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

