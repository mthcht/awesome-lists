rule Ransom_Win64_Satwancrypt_A_2147723480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Satwancrypt.A"
        threat_id = "2147723480"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Satwancrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 66 00 00 c7 43 ?? 20 00 00 00}  //weight: 1, accuracy: Low
        $x_3_2 = {b9 25 00 00 00 e8 ?? ?? 00 00 48 8d 55 ?? b9 26 00 00 00 e8 ?? ?? 00 00 41 8b ce 66 44 39 b5 f0 02 00 00 74}  //weight: 3, accuracy: Low
        $x_2_3 = {3d bc ff 9f 00 0f 87 ?? ?? 00 00 4d 85 c9 74 ?? 33 c9 42 8a 04 09 48 ff c1 88 44 0c ?? 48 81 f9 02 01 00 00 72}  //weight: 2, accuracy: Low
        $x_2_4 = {41 f6 c2 02 b8 00 f7 04 84 ba 00 f7 44 84 0f 45 c2 41 8b f9 41 f6 c2 04 74 04 0f ba e8 17}  //weight: 2, accuracy: High
        $x_1_5 = {00 2e 73 74 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 2a 70 73 70 69 6d 61 67 65 2a 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 2a 69 6e 63 70 61 73 2a 00}  //weight: 1, accuracy: High
        $x_1_8 = "S:(ML;;NRNWNX;;;LW)" ascii //weight: 1
        $x_1_9 = {40 55 53 56 57 41 54 41 55 41 56 41 57 48 8d 6c}  //weight: 1, accuracy: High
        $x_1_10 = {00 61 65 69 6f 75 79 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 62 63 64 66 67 68 6b 6c 6d 6e 70 71 72 73 74 76 77 78 7a 00}  //weight: 1, accuracy: High
        $x_1_12 = "rd /S /Q \"%s\"" ascii //weight: 1
        $x_1_13 = "del /F \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

