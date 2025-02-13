rule Trojan_Win64_GoldFinder_A_2147775900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoldFinder.A!dha"
        threat_id = "2147775900"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoldFinder"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {15 00 2f 74 6d 70 2f 66 69 6e 64 65 72 2e 67 6f 00 ?? 76 61 72 2f 77 77 77 2f 68 74 6d 6c 2f 67 6f 2f 73 72 63 2f 6e 65 74 2f 68 74 74 70 2f 66 73 2e 67 6f 00 2f 76 ?? 72 2f 77 77 77 2f 68 74 6d 6c 2f 67 6f 2f}  //weight: 5, accuracy: Low
        $x_1_2 = {54 61 72 67 65 74 3a 54 69 62 65 ?? 61 6e 54 69 72 68 75 74 61}  //weight: 1, accuracy: Low
        $x_1_3 = {53 74 61 74 75 73 43 6f 64 65 3a 54 45 53 54 49 4e 47 ?? 4b 45 59 54 54 4c}  //weight: 1, accuracy: Low
        $x_1_4 = {48 65 61 64 65 72 73 3a 48 69 72 ?? 67 61 6e 61}  //weight: 1, accuracy: Low
        $x_1_5 = {44 61 74 61 3a 44 6f 67 72 61 ?? 43 44 53 41}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 6f 63 61 74 69 6f 6e 4d 61 68 ?? 6a 61 6e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

