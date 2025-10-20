rule TrojanSpy_Win64_Hyrax_A_2147955641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Hyrax.A"
        threat_id = "2147955641"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Hyrax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 4f 53 54 20 2f 69 6e 63 6f 6d 65 5f 73 68 69 74 20 48 54 54 50 2f 31 2e 30 0d 0a ?? ?? ?? ?? 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74 2f 70 6c 61 69 6e 0d 0a 00 00 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a}  //weight: 2, accuracy: Low
        $x_1_2 = {55 72 69 3a 20 25 73 0a 55 73 65 72 3a 20 25 73 0a 50 61 73 73 3a 20}  //weight: 1, accuracy: High
        $x_1_3 = {63 6f 6e 6e 73 74 6f 72 65 2e 64 61 74 ?? ?? ?? 75 72 69 3a 20}  //weight: 1, accuracy: Low
        $x_2_4 = {0f 57 c8 0f 11 0c 0a 83 c1 10 83 f9 30 7c ?? 6a 00 6a 34 56}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

