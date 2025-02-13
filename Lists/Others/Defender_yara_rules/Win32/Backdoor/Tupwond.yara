rule Backdoor_Win32_Tupwond_B_2147614441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tupwond.B"
        threat_id = "2147614441"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tupwond"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 26 8b 4c 24 04 53 b2 ?? 80 7c 24 10 00 8a 1c 08 74 06 02 da 32 da eb 04 32 da 2a da 88 1c 08 40 3b 44 24 0c 7c e2}  //weight: 2, accuracy: Low
        $x_2_2 = {83 c3 ae 56 53 57 ff 15 ?? ?? 00 10 83 c4 0c 85 c0 0f 85 ?? ?? ?? ?? 55 8b 35 ?? ?? 00 10 57 6a 01 5b 53 6a 14 68 ?? ?? 00 10 ff d6}  //weight: 2, accuracy: Low
        $x_1_3 = {64 6f 77 6e 7c 64 6f 77 6e 72 75 6e 20 75 72 69 20 53 61 76 65 50 61 74 68 0a}  //weight: 1, accuracy: High
        $x_1_4 = {70 75 74 7c 70 75 74 72 75 6e 20 4c 6f 63 61 6c 46 69 6c 65 20 52 65 6d 6f 74 65 46 69 6c 65 0a}  //weight: 1, accuracy: High
        $x_1_5 = {70 6b 69 6c 6c 20 50 72 6f 63 65 73 73 4e 61 6d 65 7c 70 69 64 0a}  //weight: 1, accuracy: High
        $x_1_6 = "---FindPass---" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

