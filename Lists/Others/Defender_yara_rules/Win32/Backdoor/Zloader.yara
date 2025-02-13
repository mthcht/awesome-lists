rule Backdoor_Win32_Zloader_STA_2147766907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.STA"
        threat_id = "2147766907"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 61 72 72 79 2e 64 6c 6c 00 41 62 6c 65}  //weight: 1, accuracy: High
        $x_1_2 = {81 c1 08 16 00 00 02 d8 8d 42 55 03 c1 88 1d be c9 18 01 69 c0 20 64 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_STA_2147766907_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.STA"
        threat_id = "2147766907"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 72 65 2e 64 6c 6c 00 53 68 65 65 74 70 6c 61 6e}  //weight: 1, accuracy: High
        $x_1_2 = {2a c2 83 c3 13 8a d0 69 f3 48 04 01 00 c0 e0 03 02 d0 c0 e2 03 80 c2 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_STA_2147766907_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.STA"
        threat_id = "2147766907"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 65 61 72 2e 64 6c 6c 00 4d 65 65 69 67 68 74}  //weight: 1, accuracy: High
        $x_1_2 = {c7 05 78 47 04 01 11 01 00 00 8d 51 b8 03 d6 69 c2 31 b4 00 00 89 15 08 48 04 01 2b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_STA_2147766907_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.STA"
        threat_id = "2147766907"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 72 6f 70 2e 64 6c 6c 00 42 61 6c 6c 62 72 6f 77 6e}  //weight: 1, accuracy: High
        $x_1_2 = {ba 95 25 00 00 41 2b d1 8b c2 c1 e0 06 2b c2 03 c1 89 15 98 e0 08 10 a3 08 e0 08 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_STA_2147766907_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.STA"
        threat_id = "2147766907"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 68 65 65 6c 2e 64 6c 6c 00 43 6f 6e 73 6f 6e 61 6e 74 71 75 6f 74 69 65 6e 74}  //weight: 1, accuracy: High
        $x_1_2 = {69 ff dc d7 00 00 8b d0 2b d7 f6 2d 23 e0 08 10 a2 23 e0 08 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_STA_2147766907_5
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.STA"
        threat_id = "2147766907"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 78 70 65 72 69 65 6e 63 65 2e 64 6c 6c 00 53 61 77 70 61 79}  //weight: 1, accuracy: High
        $x_1_2 = {c7 05 78 47 04 01 34 01 00 00 2b cb 39 3d 90 47 04 01 72 24 8d 34 76 81 c6 9e 2f 01 00 8b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_STA_2147766907_6
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.STA"
        threat_id = "2147766907"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 6f 75 72 2e 64 6c 6c 00 4e 61 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = {69 c2 a1 d7 00 00 89 54 24 0c 2b c3 8a 3d 85 b9 18 01 8a 1d 83 b9 18 01 83 e8 07 80 ff 08 72 18 69 c8 a3 d7 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_STB_2147766908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.STB"
        threat_id = "2147766908"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 05 25 38 0a 10 0f a4 df 01 89 44 24 1c 03 db a2 1e 38 0a 10 8b 44 24 14 81 c3 81 bf fe ff 83 d7 ff}  //weight: 1, accuracy: High
        $x_10_2 = {75 70 81 78 14 20 05 93 19 74 12 81 78 14 21 05 93 19 74 09 81 78 14 22 05 93 19}  //weight: 10, accuracy: High
        $x_1_3 = {02 c1 8a d1 0f b6 c0 6b c0 ?? 2a d0 80 ea}  //weight: 1, accuracy: Low
        $x_2_4 = {81 c1 40 25 ff ff 0f b7 c0 03 d1 0f b6 0d a6 98 0a 10 89 44 24 18 0f b6 05 a8 98 0a 10 2b c8 81 f9 c3 01 00 00 74 16 a1 b8 98 0a 10 bb 5b 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = {81 f7 6e 74 65 6c 8b 45 e8 35 69 6e 65 49 89 45 f8 8b 45 e0 35 47 65 6e 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_STC_2147766916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.STC"
        threat_id = "2147766916"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 1e 00 00 [0-7] 55 11 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = "Software\\Microsoft\\COMSpy" ascii //weight: 10
        $x_10_3 = {00 46 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_1_4 = {6a 00 6a 01 6a 00 6a 00 8d 45 fc 50 ff 15 ?? ?? ?? ?? 85 c0 75 04 33 c0 eb 1c 6a 08 6a 01 6a 00 6a 00 8d 4d fc 51 ff}  //weight: 1, accuracy: Low
        $x_1_5 = {41 b9 01 00 00 00 45 33 c0 33 d2 48 8d 4c ?? ?? ff 15 ?? ?? ?? ?? 85 c0 75 [0-6] c7 ?? ?? ?? 08 00 00 00 41 b9 01 00 00 00 45 33 c0 33 d2 48 8d 4c 09 30 01 02 ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {41 bf 01 00 00 00 48 8d 4d 48 45 33 c0 33 d2 45 8b cf 89 45 38 ff 15 ?? ?? ?? ?? 85 c0 75 43 48 8d 4d 48 45 8b cf 45 33 c0 33 d2 c7 44 24 20 08 00 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zloader_ST_2147767137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.ST!!Zloader.ST"
        threat_id = "2147767137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "Zloader: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 61 72 72 79 2e 64 6c 6c 00 41 62 6c 65}  //weight: 1, accuracy: High
        $x_1_2 = {81 c1 08 16 00 00 02 d8 8d 42 55 03 c1 88 1d be c9 18 01 69 c0 20 64 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_ST_2147767137_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.ST!!Zloader.ST"
        threat_id = "2147767137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "Zloader: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 72 65 2e 64 6c 6c 00 53 68 65 65 74 70 6c 61 6e}  //weight: 1, accuracy: High
        $x_1_2 = {2a c2 83 c3 13 8a d0 69 f3 48 04 01 00 c0 e0 03 02 d0 c0 e2 03 80 c2 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_ST_2147767137_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.ST!!Zloader.ST"
        threat_id = "2147767137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "Zloader: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 65 61 72 2e 64 6c 6c 00 4d 65 65 69 67 68 74}  //weight: 1, accuracy: High
        $x_1_2 = {c7 05 78 47 04 01 11 01 00 00 8d 51 b8 03 d6 69 c2 31 b4 00 00 89 15 08 48 04 01 2b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_ST_2147767137_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.ST!!Zloader.ST"
        threat_id = "2147767137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "Zloader: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 72 6f 70 2e 64 6c 6c 00 42 61 6c 6c 62 72 6f 77 6e}  //weight: 1, accuracy: High
        $x_1_2 = {ba 95 25 00 00 41 2b d1 8b c2 c1 e0 06 2b c2 03 c1 89 15 98 e0 08 10 a3 08 e0 08 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_ST_2147767137_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.ST!!Zloader.ST"
        threat_id = "2147767137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "Zloader: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 68 65 65 6c 2e 64 6c 6c 00 43 6f 6e 73 6f 6e 61 6e 74 71 75 6f 74 69 65 6e 74}  //weight: 1, accuracy: High
        $x_1_2 = {69 ff dc d7 00 00 8b d0 2b d7 f6 2d 23 e0 08 10 a2 23 e0 08 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_ST_2147767137_5
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.ST!!Zloader.ST"
        threat_id = "2147767137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "Zloader: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 78 70 65 72 69 65 6e 63 65 2e 64 6c 6c 00 53 61 77 70 61 79}  //weight: 1, accuracy: High
        $x_1_2 = {c7 05 78 47 04 01 34 01 00 00 2b cb 39 3d 90 47 04 01 72 24 8d 34 76 81 c6 9e 2f 01 00 8b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_ST_2147767137_6
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.ST!!Zloader.ST"
        threat_id = "2147767137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "Zloader: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 6f 75 72 2e 64 6c 6c 00 4e 61 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = {69 c2 a1 d7 00 00 89 54 24 0c 2b c3 8a 3d 85 b9 18 01 8a 1d 83 b9 18 01 83 e8 07 80 ff 08 72 18 69 c8 a3 d7 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_ST_2147767137_7
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.ST!!Zloader.ST"
        threat_id = "2147767137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "Zloader: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 6d 6f 64 75 6c 65 63 6f 6e 66 69 67 3e [0-4] 3c 6e 65 65 64 69 6e 66 6f 20 6e 61 6d 65 3d 22 69 64 22 2f 3e [0-4] 3c 61 75 74 6f 63 6f 6e 66 3e [0-4] 3c 63 6f 6e 66 20 63 74 6c 3d 22 73 72 76 22 20 66 69 6c 65 3d 22 73 72 76 22 20 70 65 72 69 6f 64 3d 22 36 30 22 2f 3e [0-4] 3c 2f 61 75 74 6f 63 6f 6e 66 3e [0-4] 3c 2f 6d 6f 64 75 6c 65 63 6f 6e 66 69 67 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zloader_SD_2147767427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zloader.SD!MTB"
        threat_id = "2147767427"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tmp.txt" ascii //weight: 1
        $x_1_2 = {00 d0 89 c3 89 d8 8b 4d 08 00 c8 f6 e2 30 d8 0f be c0 a3 ?? ?? ?? ?? 89 f8 5e 5f 5b 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 0c 85 c9 0f 84 ?? 00 00 00 a1 ?? ?? ?? ?? 0f be 18 66 33 1e 66 89 19 0f 84 ?? 00 00 00 31 ff e9 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

