rule Trojan_Win64_BarrelHoncho_A_2147951791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BarrelHoncho.A"
        threat_id = "2147951791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BarrelHoncho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 20 25 6c 75 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 20 25 6c 75 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 20 25 6c 75 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 68 65 20 70 72 69 76 69 6c 65 67 65 20 25 73 20 69 73 20 6e 6f 74 20 61 73 73 69 67 6e 65 64 20 74 6f 20 74 68 65 20 63 61 6c 6c 65 72 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 65 6e 61 62 6c 65 64 20 25 73 20 70 72 69 76 69 6c 65 67 65 2e 0a 00}  //weight: 1, accuracy: High
        $x_10_6 = {48 03 d2 48 c1 ca 20 49 0f af ?? 48 c1 ?? 21 48 03 ?? 48 c1 ca 1f 0f b6 ?? 42 32}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

