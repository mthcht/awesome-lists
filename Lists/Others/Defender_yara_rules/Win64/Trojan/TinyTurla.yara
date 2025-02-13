rule Trojan_Win64_TinyTurla_B_2147926511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TinyTurla.B!dha"
        threat_id = "2147926511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TinyTurla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 44 05 42 5c 00 50 00 c7 44 05 46 61 00 72 00 c7 44 05 4a 61 00 6d 00 c7 44 05 4e 65 00 74 00 c7 44 05 52 65 00 72 00 c7 44 05 56 73 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {c7 00 53 00 59 00 c7 40 04 53 00 54 00 c7 40 08 45 00 4d 00 c7 40 0c 5c 00 43 00 c7 40 10 75 00 72 00 c7 40 14 72 00 65 00 c7 40 18 6e 00 74 00 c7 40 1c 43 00 6f 00 c7 40 20 6e 00 74 00 c7 40 24 72 00 6f 00 c7 40 28 6c 00 53 00 c7 40 2c 65 00 74 00 c7 40 30 5c 00 53 00 c7 40 34 65 00 72 00 c7 40 38 76 00 69 00 c7 40 3c 63 00 65 00 c7 40 40 73 00 5c 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

