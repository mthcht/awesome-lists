rule Ransom_Win32_Pottieq_A_2147708495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pottieq.A"
        threat_id = "2147708495"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pottieq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/stat/" ascii //weight: 1
        $x_1_2 = "/pass/" ascii //weight: 1
        $x_1_3 = {85 c0 75 04 b3 01 eb 08 81 fe 82 00 00 00 7c e0}  //weight: 1, accuracy: High
        $x_2_4 = {3a 74 72 79 [0-16] 64 65 6c 20 22 [0-16] 22 [0-16] 69 66 20 65 78 69 73 74 20 22}  //weight: 2, accuracy: Low
        $x_2_5 = {5c 52 75 6e [0-16] 2e 65 78 65 [0-16] 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 [0-16] 2e 62 6d 70 [0-16] 57 61 6c 6c 70 61 70 65 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

