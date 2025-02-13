rule Ransom_Win32_Isda_A_2147689536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Isda.A"
        threat_id = "2147689536"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Isda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6c 65 65 6e 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 74 77 6f 40 41 55 53 49 2e 43 4f 4d 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 6b 77 6d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 6f 63 78 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 70 64 66 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 61 72 6a 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 63 73 76}  //weight: 1, accuracy: Low
        $x_1_4 = {61 66 72 69 63 61 2e 62 6d 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {66 73 61 73 67 64 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 6d 3a 5c 00}  //weight: 1, accuracy: Low
        $x_2_6 = {81 bd 10 ff ff ff 00 80 00 00 7c 09 c6 85 1f ff ff ff 20 eb 39 81 bd 10 ff ff ff 00 04 00 00 7e 26 81 bd 10 ff ff ff 00 80 00 00 7d 1a 8b 85 10 ff ff ff 85 c0 79 05 05 ff 03 00 00 c1 f8 0a 88 85 1f ff ff ff eb 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Isda_A_2147689536_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Isda.A"
        threat_id = "2147689536"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Isda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 65 6d 70 00 00 00 00 ff ff ff ff 04 00 00 00 2e 6a 70 67 00 00 00 00 ff ff ff ff 05 00 00 00 2e 6a 70 65 67 00 00 00 ff ff ff ff 04 00 00 00 2e 64 6f 63 00 00 00 00 ff ff ff ff 04 00 00 00 2e 72 74 66 00 00 00 00 ff ff ff ff 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 64 3d 00 ff ff ff ff 03 00 00 00 70 63 3d 00 ff ff ff ff 05 00 00 00 74 61 69 6c 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 73 61 73 67 64 00 00 ff ff ff ff ?? 00 00 00 [0-15] 2e 62 6d 70 00 [0-4] 68 74 31 93}  //weight: 1, accuracy: Low
        $x_1_4 = {71 3a 5c 00 ff ff ff ff 03 00 00 00 74 3a 5c 00 ff ff ff ff 03 00 00 00 73 3a 5c 00 ff ff ff ff 03 00 00 00 76 3a 5c 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 63 6c 6f 73 65 2f 73 63 72 69 70 74 2e 70 68 70 00 00 00 ff ff ff ff ?? 00 00 00 68 74 74 70 3a 2f 2f [0-30] 2e 63 6f 6d 2f 6f 70 65 6e 2f 73 63 72 69 70 74 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

