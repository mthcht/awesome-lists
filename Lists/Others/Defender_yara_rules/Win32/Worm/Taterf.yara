rule Worm_Win32_Taterf_B_2147603086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Taterf.B"
        threat_id = "2147603086"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Taterf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "explorer.exe %s" ascii //weight: 1
        $x_1_2 = "GetInputState" ascii //weight: 1
        $x_1_3 = "CreateRemoteThread" ascii //weight: 1
        $x_1_4 = {81 7d f8 40 19 01 00 0f 87}  //weight: 1, accuracy: High
        $x_1_5 = "AlertDialog" ascii //weight: 1
        $x_2_6 = "Product_Notification" ascii //weight: 2
        $x_2_7 = {23 33 32 37 37 30 [0-5] 52 61 76 6d 6f 6e 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_8 = {53 50 ff d7 53 53 6a 10 50 ff d6 6a 01 ff 15}  //weight: 2, accuracy: High
        $x_2_9 = {eb db 57 ff d3 68 a0 0f 00 00 ff 75 fc ff 15}  //weight: 2, accuracy: High
        $x_3_10 = {83 f8 ff 89 45 d0 75 ?? ff 45 08 83 7d 08 0a 72 ?? 8d 4d e4 53 51 ff 75 d4 ff 75 fc 50}  //weight: 3, accuracy: Low
        $x_3_11 = {53 6a 01 68 01 02 00 00 ff 75 fc ff d6 53 53 68 02 02 00 00 ff 75 fc ff d6 20}  //weight: 3, accuracy: High
        $x_3_12 = {85 c0 74 15 6a 00 68 41 9c 00 00 68 11 01 00 00 ff 75 08}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Taterf_A_2147603444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Taterf.gen!A"
        threat_id = "2147603444"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Taterf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {40 83 f8 20 [0-6] 72 ?? 8b 0d ?? ?? 00 10 33 c0 85 c9 [0-16] 8a 98 ?? ?? 00 10 32 da 88 98 ?? ?? 00 10 40 3b c1 72}  //weight: 8, accuracy: Low
        $x_7_2 = {10 83 f8 03 74 09 83 f8 02 1f 00 [0-12] 43 8a 50 00 [0-38] 68 88 13 00 00 ff 15}  //weight: 7, accuracy: Low
        $x_2_3 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e 00 48 69 64 64 65 6e 00}  //weight: 2, accuracy: High
        $x_2_4 = {63 6f 63 2e 65 78 65 00 61 61 61 2e 64 61 74}  //weight: 2, accuracy: High
        $x_3_5 = {75 72 6c 69 6e 66 6f 00 43 4c 53 49 44 5c 4d 41 44 4f 57 4e}  //weight: 3, accuracy: High
        $x_1_6 = {61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_7 = "GetDriveTypeA" ascii //weight: 1
        $x_1_8 = "NoDriveTypeAutoRun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Taterf_B_2147603445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Taterf.gen!B"
        threat_id = "2147603445"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Taterf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 6e 64 6c 6c 2e 64 6c 6c 00 5a 74 47 61 6d 65 5f 49 4e 00 5a 74 47 61 6d 65 5f 4f 55 54 00 00 00 00 00 08 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Taterf_DI_2147628017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Taterf.DI!dll"
        threat_id = "2147628017"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Taterf"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shell\\open\\Command=rundll32.exe .\\" ascii //weight: 1
        $x_1_2 = "CLSID\\{0010BB0C-2F85-46C3-B06A-0F87BB08646C}\\InProcServer32" ascii //weight: 1
        $x_2_3 = {b0 65 aa b0 78 aa b0 70 aa b0 6c aa b0 6f aa b0 72 aa b0 65 aa b0 72 aa b0 2e aa b0 65 aa b0 78 aa b0 65 aa 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Taterf_DM_2147633114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Taterf.DM"
        threat_id = "2147633114"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Taterf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 83 7d fc 00 0f 84 ?? ?? ?? ?? 81 7b ?? 90 90 90 90 75 ?? cc}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d6 83 7d fc 00 74 ?? 80 bd ?? ?? ?? ?? b8 74}  //weight: 1, accuracy: Low
        $x_2_3 = {51 6a 0b ff d0 8b 45 fc 85 c0 75 ?? cc e9 ?? ?? ?? ?? 69 c0 1c 01 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {83 c0 b0 51 8d 8d ?? ?? ?? ?? 68 00 01 00 00 51 50 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 80 bd ?? ?? ?? ?? b8}  //weight: 2, accuracy: Low
        $x_2_5 = {ff d6 bf ff ff 00 00 23 c7 3d 16 1c 00 00 76 ?? 3d 20 1c 00 00 73 ?? ff 75 14 ff 75 10 ff 75 0c ff 75 0c e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Taterf_E_2147654545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Taterf.gen!E"
        threat_id = "2147654545"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Taterf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 30 f0 ff ff 8d bc 05 f8 ef ff ff 0f b7 84 05 08 f0 ff ff 8d 77 14 03 c6 89 45 f4 8b 45 10 3b c3 74 05 8b 4e 1c 89 08 ff 76 38 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Taterf_E_2147654545_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Taterf.gen!E"
        threat_id = "2147654545"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Taterf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 25 ff ff 00 00 3d 16 1c 00 00 76 08 3d 20 1c 00 00 73 01 cc}  //weight: 1, accuracy: High
        $x_1_2 = {ff d6 bf ff ff 00 00 23 c7 3d 16 1c 00 00 76 (?? 3d 20 1c 00 00 73 ??|0f 3d 20 1c 00 00 73 08 6a 00)}  //weight: 1, accuracy: Low
        $x_1_3 = {58 83 38 00 75 1f ff 00 ff 74 24 10 ff 74 24 10 ff 74 24 10 ff 74 24 10 09 00 e8 04 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

