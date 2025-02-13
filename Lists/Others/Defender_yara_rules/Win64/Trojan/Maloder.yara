rule Trojan_Win64_Maloder_A_2147922593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Maloder.A"
        threat_id = "2147922593"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Maloder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6b 00 65 00 [0-6] 72 00 6e 00}  //weight: 2, accuracy: Low
        $x_1_2 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 59 10}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 0c 53 41 8b 04 8b 49 03 c1 eb e3}  //weight: 1, accuracy: High
        $x_1_4 = {ba 42 31 0e 00}  //weight: 1, accuracy: High
        $x_1_5 = {ba 86 57 0d 00}  //weight: 1, accuracy: High
        $x_1_6 = {ba fa 8b 34 00}  //weight: 1, accuracy: High
        $x_1_7 = {8a 44 0c 20 ?? 32 04 ?? 41 88}  //weight: 1, accuracy: Low
        $x_1_8 = {8a 44 0c 24 32 87 ?? ?? ?? ?? 88 04 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

