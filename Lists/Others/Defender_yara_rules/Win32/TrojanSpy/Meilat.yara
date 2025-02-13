rule TrojanSpy_Win32_Meilat_A_2147678411_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Meilat.A"
        threat_id = "2147678411"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Meilat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 2a 00 2e 00 6d 00 61 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 2a 00 2e 00 77 00 61 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "908F6D9268CC94A57C8196AB" ascii //weight: 1
        $x_1_5 = {2f 65 6e 76 69 61 6d 61 69 6c 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Meilat_B_2147678412_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Meilat.B"
        threat_id = "2147678412"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Meilat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 70 67 74 5f 69 70 76 61 5f 6f 6b 2e 70 68 70 3f 69 64 70 63 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 73 74 61 74 75 73 3d 45 66 65 74 75 61 64 6f 5f 50 47 54 5f 49 50 56 41 5f 52 24 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 61 70 6c 2f 63 6f 6d 75 6d 2f 69 6d 61 67 65 6e 73 6e 69 2f 62 74 5f 63 6f 6e 66 69 72 6d 61 72 2e 67 69 66 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 63 61 64 5f 6e 65 74 2e 70 68 70 3f 26 69 64 70 63 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 68 6f 6d 65 2f 43 61 6d 70 61 6e 68 61 56 65 72 69 66 69 63 61 54 49 2e 64 6f 3f 43 54 52 4c 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 74 65 73 74 65 5c 6c 6f 67 73 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 6e 61 6d 65 70 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = "TFormdoor" ascii //weight: 1
        $x_1_9 = "Tformprincipal" ascii //weight: 1
        $x_1_10 = "\\Bho NET EMPRESA\\Bho\\" ascii //weight: 1
        $x_1_11 = {2f 70 65 73 71 75 69 73 61 63 61 64 2e 70 68 70 3f 26 6e 61 6d 65 70 63 3d 00}  //weight: 1, accuracy: High
        $x_1_12 = {2f 73 65 6c 65 63 74 5f 62 6f 6c 65 74 61 5f 70 61 67 61 72 2e 70 68 70 3f 26 63 6f 64 62 61 72 72 61 3d 00}  //weight: 1, accuracy: High
        $x_1_13 = {4e e3 6f 20 66 6f 69 20 70 6f 73 73 ed 76 65 6c 20 61 75 74 65 6e 74 69 63 61 72 20 6f 20 63 f3 64 69 67 6f 20 64 65 20 73 65 75 20 74 6f 6b 65 6e}  //weight: 1, accuracy: High
        $x_1_14 = {2f 73 65 6c 65 63 74 5f 63 6f 6e 73 75 6d 6f 5f 70 61 67 61 72 2e 70 68 70 3f 26 63 6f 64 62 61 72 72 61 3d 00}  //weight: 1, accuracy: High
        $x_1_15 = {2f 73 65 74 5f 6f 6e 6c 69 6e 65 5f 6c 6f 67 69 6e 2e 70 68 70 3f 6e 61 6d 65 70 63 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

