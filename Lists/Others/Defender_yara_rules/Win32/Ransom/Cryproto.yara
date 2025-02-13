rule Ransom_Win32_Cryproto_A_2147708298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryproto.A"
        threat_id = "2147708298"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryproto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {44 00 45 00 53 00 4b 00 52 00 59 00 50 00 54 00 45 00 44 00 4e 00 38 00 31 00 40 00 47 00 4d 00 41 00 49 00 4c 00 2e 00 43 00 4f 00 4d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "!crypt" wide //weight: 1
        $x_1_4 = "!.crypt" wide //weight: 1
        $x_1_5 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 72 00 6f 00 74 00 6f 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {44 00 49 00 52 00 45 00 43 00 54 00 4f 00 52 00 41 00 54 00 31 00 43 00 40 00 47 00 4d 00 41 00 49 00 4c 00 2e 00 43 00 4f 00 4d 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 43 00 52 00 59 00 50 00 54 00 4e 00 31 00 40 00 47 00 4d 00 41 00 49 00 4c 00 2e 00 43 00 4f 00 4d 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {2e 00 2d 00 2e 00 72 00 6f 00 74 00 6f 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {2e 00 72 00 6f 00 74 00 6f 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 61 00 70 00 70 00 73 00 68 00 65 00 6c 00 70 00 40 00 6d 00 61 00 69 00 6c 00 2e 00 72 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {66 c7 44 7e 0c 74 00 66 c7 44 7e 0a 70 00 66 c7 44 7e 08 79 00 66 c7 44 7e 06 72 00 66 c7 44 7e 04 63 00 66 c7 44 7e 02 2e 00 66 c7 44 7e 0e 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {66 c7 44 7e 1c 78 00 66 89 4c 7e 18 66 c7 44 7e 14 70 00 66 c7 44 7e 12 79 00 66 c7 44 7e 10 72 00 66 c7 44 7e 0e 63 00 66 89 4c 7e 0c 66 89 44 7e 0a 66 c7 44 7e 08 6d 00 66 c7 44 7e 06 64 00 66 c7 44 7e 04 61 00 66 89 44 7e 02}  //weight: 1, accuracy: High
        $x_1_13 = {c6 44 24 10 64 c6 44 24 0f 2e c6 44 24 0e 32 c6 44 24 0d 33 c6 44 24 0c 74 c6 44 24 0b 70 c6 44 24 0a 79 c6 44 24 09 72}  //weight: 1, accuracy: High
        $x_1_14 = {66 c7 44 24 18 35 00 66 c7 44 24 16 63 00 66 c7 44 24 14 6c 00 66 c7 44 24 12 61 00 66 c7 44 24 10 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cryproto_B_2147717029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryproto.B"
        threat_id = "2147717029"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryproto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {66 c7 44 24 ?? 6b 00}  //weight: 20, accuracy: Low
        $x_20_2 = {68 02 9f e6 6a e8}  //weight: 20, accuracy: High
        $x_20_3 = {a8 01 74 09 d1 e8 35 ?? ?? ?? ?? eb}  //weight: 20, accuracy: Low
        $x_10_4 = {68 c8 af 00 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 6b c9 64 b8 73 b2 e7 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*))) or
            (all of ($x*))
        )
}

