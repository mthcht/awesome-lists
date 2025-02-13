rule Backdoor_Win32_Psatela_STA_2147773154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Psatela.STA"
        threat_id = "2147773154"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Psatela"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 91 06 61 20 ?? 00 00 00 61 d2 9c 06 17 58 0a 06 7e ?? ?? 00 04 8e 69 fe 04 2d}  //weight: 2, accuracy: Low
        $x_2_2 = {4e 45 57 42 4d 50 f9 e4 ee fd f9 ee fe e8 fe ee c9 c2 d4 c8 d7 ca dc cf}  //weight: 2, accuracy: High
        $x_1_3 = {4b 69 6c 6c [0-16] 53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 41 63 63 65 73 73 43 6f 6e 74 72 6f 6c [0-26] 53 65 74 41 63 63 65 73 73 43 6f 6e 74 72 6f 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {43 6f 70 79 46 72 6f 6d 53 63 72 65 65 6e [0-10] 67 65 74 5f 50 72 69 6d 61 72 79 53 63 72 65 65 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {6c 70 53 74 61 72 74 75 70 49 6e 66 6f [0-10] 47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f}  //weight: 1, accuracy: Low
        $x_1_6 = {42 65 67 69 6e 52 65 63 65 69 76 65 [0-16] 2e 65 78 65 [0-10] 64 77 58 53 69 7a 65}  //weight: 1, accuracy: Low
        $x_1_7 = {41 73 79 6e 63 43 61 6c 6c 62 61 63 6b 00 52 65 63 69 65 76 65 43 61 6c 6c 62 61 63 6b 00 54 69 6d 65 72 43 61 6c 6c 62 61 63 6b}  //weight: 1, accuracy: High
        $x_1_8 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 44 65 6c 65 74 65 46 69 6c 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Psatela_STA_2147773155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Psatela.STA!!Psatela.STA"
        threat_id = "2147773155"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Psatela"
        severity = "Critical"
        info = "Psatela: an internal category used to refer to some threats"
        info = "STA: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 91 06 61 20 ?? 00 00 00 61 d2 9c 06 17 58 0a 06 7e ?? ?? 00 04 8e 69 fe 04 2d}  //weight: 2, accuracy: Low
        $x_2_2 = {4e 45 57 42 4d 50 f9 e4 ee fd f9 ee fe e8 fe ee c9 c2 d4 c8 d7 ca dc cf}  //weight: 2, accuracy: High
        $x_1_3 = {4b 69 6c 6c [0-16] 53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 41 63 63 65 73 73 43 6f 6e 74 72 6f 6c [0-26] 53 65 74 41 63 63 65 73 73 43 6f 6e 74 72 6f 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {43 6f 70 79 46 72 6f 6d 53 63 72 65 65 6e [0-10] 67 65 74 5f 50 72 69 6d 61 72 79 53 63 72 65 65 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {6c 70 53 74 61 72 74 75 70 49 6e 66 6f [0-10] 47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f}  //weight: 1, accuracy: Low
        $x_1_6 = {42 65 67 69 6e 52 65 63 65 69 76 65 [0-16] 2e 65 78 65 [0-10] 64 77 58 53 69 7a 65}  //weight: 1, accuracy: Low
        $x_1_7 = {41 73 79 6e 63 43 61 6c 6c 62 61 63 6b 00 52 65 63 69 65 76 65 43 61 6c 6c 62 61 63 6b 00 54 69 6d 65 72 43 61 6c 6c 62 61 63 6b}  //weight: 1, accuracy: High
        $x_1_8 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 44 65 6c 65 74 65 46 69 6c 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

