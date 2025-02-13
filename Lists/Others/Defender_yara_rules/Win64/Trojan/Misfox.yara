rule Trojan_Win64_Misfox_A_2147727843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Misfox.A!dha"
        threat_id = "2147727843"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Misfox"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 6c 6f 62 61 6c 5c 6d 73 69 66 66 30 78 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 6c 64 2e 73 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 30 66 35 38 37 37 62 64 61 39 31 30 66 32 37 38 34 30 66 32 65 32 31 34 36 31 37 32 33 66 31 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 6c 6c 36 34 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_3_5 = {48 63 c3 c6 44 04 38 2e ff c3 48 63 c3 c6 44 04 38 72 ff c3 48 63 c3 c6 44 04 38 75 8d 43 01 48 63 c8 48 83 f9 10 73 33 c6 44 0c 38 00 80 7c 24 38 00 74 12 48 8d 44 24 38 48 83 ce ff 48 ff c6}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

