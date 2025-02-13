rule Worm_Win32_Regul_A_2147610091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Regul.A"
        threat_id = "2147610091"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Regul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 52 65 63 79 63 6c 65 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 78 70 6c 6f 72 65 72 20 00 2e 65 78 65 00 72 65 73 74 61 72 74}  //weight: 1, accuracy: High
        $x_1_3 = {72 65 67 77 77 77 00 75 6c 2e 64 6c 6c 00 6f 67 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_4 = {40 20 72 65 73 74 61 72 74 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: High
        $x_1_5 = "keybd_event" ascii //weight: 1
        $x_1_6 = "GetTempPathA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Regul_D_2147610397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Regul.D"
        threat_id = "2147610397"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Regul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 6f 70 65 6e 00 41 75 74 6f 52 75 6e 00 b4 f2 bf aa 28 26 4f 29 00}  //weight: 4, accuracy: High
        $x_2_2 = {58 50 2d 00 65 78 70 6c 6f 72 65 72 20 00 2e 65 78 65 00 72 65 73 74 61 72 74}  //weight: 2, accuracy: High
        $x_1_3 = "WM_HTML_GETOBJECT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Regul_B_2147617086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Regul.B"
        threat_id = "2147617086"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Regul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 72 6e 6c 6e 2e 66 6e 65 00 00 00 6b 72 6e 6c 6e 2e 66 6e 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 63 6e 2f 75 6c 2e 68 74 6d 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_3 = {00 2e 63 6f 6d 2f 75 6c 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 78 70 6c 6f 72 65 72 20 00 2e 65 78 65 00 72 65 73 74 61 72 74 00 72 65 67}  //weight: 1, accuracy: High
        $x_1_5 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 6f 70 65 6e 00 41 75 74 6f 52 75 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Regul_C_2147626431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Regul.C"
        threat_id = "2147626431"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Regul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetTempPathA" ascii //weight: 1
        $x_1_2 = {2e 63 6e 2f 75 6c 2e 68 74 6d 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_3 = {00 2e 63 6f 6d 2f 75 6c 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 78 70 6c 6f 72 65 72 20 00 2e 65 78 65 00 72 65 73 74 61 72 74 00 72 65 67}  //weight: 1, accuracy: High
        $x_1_5 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 6f 70 65 6e 00 41 75 74 6f 52 75 6e}  //weight: 1, accuracy: High
        $x_1_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 00 4d 30 38 30 38 30 31 00 4e 6f 74 65 70 61 64 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

