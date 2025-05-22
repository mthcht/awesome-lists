rule Ransom_Win32_Vanhelsing_DA_2147936357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Vanhelsing.DA!MTB"
        threat_id = "2147936357"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Vanhelsing"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = ".vanhelsing" ascii //weight: 50
        $x_50_2 = {76 00 61 00 6e 00 68 00 65 00 6c 00 [0-100] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00}  //weight: 50, accuracy: Low
        $x_50_3 = {76 61 6e 68 65 6c [0-100] 2e 6f 6e 69 6f 6e}  //weight: 50, accuracy: Low
        $x_1_4 = {73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-30] 64 00 65 00 6c 00 65 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {73 68 61 64 6f 77 63 6f 70 79 [0-30] 64 65 6c 65 74 65}  //weight: 1, accuracy: Low
        $x_1_6 = "Download tor browser" ascii //weight: 1
        $x_1_7 = "lose all your date" ascii //weight: 1
        $x_1_8 = "pay the ransom" ascii //weight: 1
        $x_1_9 = "restore your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 4 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Vanhelsing_AA_2147942026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Vanhelsing.AA"
        threat_id = "2147942026"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Vanhelsing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "VanHelsing Ransomeware" wide //weight: 10
        $x_10_2 = {00 47 6c 6f 62 61 6c 5c 56 61 6e 48 65 6c 73 69 6e 67 00}  //weight: 10, accuracy: High
        $x_10_3 = {00 00 76 00 68 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 70 00 6e 00 67 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {00 00 76 00 68 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 69 00 63 00 6f 00 00 00}  //weight: 10, accuracy: High
        $x_10_5 = {00 52 45 41 44 4d 45 2e 74 78 74 00}  //weight: 10, accuracy: High
        $x_1_6 = {2e 00 76 00 61 00 6e 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2e 00 76 00 61 00 6e 00 68 00 65 00 6c 00 73 00 69 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Vanhelsing_AB_2147942027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Vanhelsing.AB"
        threat_id = "2147942027"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Vanhelsing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 00 2d 00 2d 00 53 00 69 00 6c 00 65 00 6e 00 74 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 00 2d 00 2d 00 6e 00 6f 00 2d 00 70 00 72 00 69 00 6f 00 72 00 69 00 74 00 79 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {00 00 2d 00 2d 00 6e 00 6f 00 2d 00 77 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {00 00 2d 00 2d 00 6e 00 6f 00 2d 00 6c 00 6f 00 63 00 61 00 6c 00 00 00}  //weight: 10, accuracy: High
        $x_10_5 = {00 00 2d 00 2d 00 73 00 70 00 72 00 65 00 61 00 64 00 2d 00 73 00 6d 00 62 00 00 00}  //weight: 10, accuracy: High
        $x_10_6 = {5b 00 2a 00 5d 00 09 00 4c 00 6f 00 63 00 6b 00 69 00 6e 00 67 00 20 00 66 00 69 00 6c 00 65 00 20 00 64 00 6f 00 6e 00 65 00 20 00 2e 00 2e 00 2e 00 0a 00 00 00}  //weight: 10, accuracy: High
        $x_10_7 = {5b 00 2a 00 5d 00 09 00 73 00 74 00 61 00 72 00 74 00 20 00 4c 00 6f 00 63 00 6b 00 69 00 6e 00 67 00 20 00 2e 00 2e 00 2e 00 0a 00 00 00}  //weight: 10, accuracy: High
        $x_10_8 = {5b 00 2a 00 5d 00 20 00 46 00 69 00 6c 00 65 00 20 00 25 00 73 00 20 00 4c 00 4f 00 43 00 4b 00 45 00 44 00 20 00 53 00 55 00 43 00 43 00 45 00 53 00 53 00 46 00 55 00 4c 00 4c 00 59 00 0a 00 00 00}  //weight: 10, accuracy: High
        $x_1_9 = {2d 00 2d 00 2d 00 6b 00 65 00 79 00 2d 00 2d 00 2d 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {2d 00 2d 00 2d 00 65 00 6e 00 64 00 6b 00 65 00 79 00 2d 00 2d 00 2d 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {2d 00 2d 00 2d 00 6e 00 6f 00 6e 00 63 00 65 00 2d 00 2d 00 2d 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {2d 00 2d 00 2d 00 65 00 6e 00 64 00 6e 00 6f 00 6e 00 63 00 65 00 2d 00 2d 00 2d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

