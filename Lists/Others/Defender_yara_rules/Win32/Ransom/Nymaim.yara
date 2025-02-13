rule Ransom_Win32_Nymaim_A_2147672535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nymaim.A"
        threat_id = "2147672535"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 08 00 20 20 20}  //weight: 1, accuracy: High
        $x_1_2 = {81 38 2e 74 6f 72 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {81 48 04 20 20 20 20}  //weight: 1, accuracy: High
        $x_1_4 = {81 78 04 72 65 6e 74}  //weight: 1, accuracy: High
        $x_1_5 = {66 69 6c 65 02 00 (c7 03|8d 15)}  //weight: 1, accuracy: Low
        $x_1_6 = {c7 43 04 6e 61 6d 65}  //weight: 1, accuracy: High
        $x_1_7 = {c6 43 08 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nymaim_B_2147678691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nymaim.B"
        threat_id = "2147678691"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 03 66 69 6c 65 (c7 43 04 6e 61|e9 c7 43 04 6e 61) [0-16] (c6 43|e9 c6 43)}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 43 08 3d 83 c3 09 ff 75 fc 50 53 e8 ?? ?? 00 00 03 5d fc c7 03 26 64 61 74 66 c7 43 04 61 3d 8d 7b 06}  //weight: 1, accuracy: Low
        $x_1_3 = {25 0f 0f 0f 0f 05 61 61 61 61 89 07 c7 47 04 2e 74 6d 70 68 09 dd ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {2f 6e 79 6d 61 69 6e 2f [0-15] 2f 69 6e 64 65 78 2e 70 68 70 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nymaim_D_2147684516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nymaim.D"
        threat_id = "2147684516"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 b9 10 27 00 00 f7 e1 8d 4d f8 f7 d8 83 d2 00 f7 da 89 01 89 51 04 51 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {89 47 01 c6 47 05 c3 ff 75 ?? (56|57) 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 40 00 c6 07 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nymaim_F_2147686321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nymaim.F"
        threat_id = "2147686321"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 06 d1 c8 40 46 49 75}  //weight: 1, accuracy: High
        $x_1_2 = {c6 06 04 c6 46 01 01 8b 02 89 c1}  //weight: 1, accuracy: High
        $x_1_3 = {59 83 e1 03 c1 e1 03 d3 cb 8a 07 30 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

