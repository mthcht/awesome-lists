rule VirTool_Win32_Rootkitdrv_DD_2147598278_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Rootkitdrv.DD"
        threat_id = "2147598278"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 25 00 53 00 00 00 63 00 73 00 72 00 73 00 73 00 2e 00 65 00 78 00 65 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54}  //weight: 3, accuracy: High
        $x_2_2 = {8a d0 0f 20 c0 89 44 24 08 0f ba f0 10 0f 22 c0 8b 44 24 10 8b 4c 24 18 49 8b 74 24 14 8b 38 f3 a5 8b 4c 24 20 49 8b 74 24 1c 8b 78 10 f3 a5}  //weight: 2, accuracy: High
        $x_1_3 = "KeRaiseIrqlToDpcLevel" ascii //weight: 1
        $x_1_4 = "KeStackAttachProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Rootkitdrv_BR_2147598712_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Rootkitdrv.BR"
        threat_id = "2147598712"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
        $x_1_2 = {83 65 fc 00 53 56 57 be 00 10 00 00 68 44 64 6b 20 56 6a 00 ff 15 [0-48] 8b d8 81 fb 04 00 00 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Rootkitdrv_BS_2147598713_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Rootkitdrv.BS"
        threat_id = "2147598713"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 48 78 c7 40 34 00 ?? 01 00 e8 ?? ?? 00 00 33 c0 c2 08 00 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 c3 [0-6] 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb c3}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ff 04 00 00 c0 75 16 81 c3 00 10 00 00 68 44 64 6b 20 53 6a 00 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Rootkitdrv_CV_2147602565_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Rootkitdrv.CV"
        threat_id = "2147602565"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 65 e8 0f 20 c0 25 ff ff fe ff 0f 22 c0 33 c0 8b 75 08 3b 06 73}  //weight: 3, accuracy: High
        $x_3_2 = {80 39 e8 75 ?? 8b 51 01 8d 54 11 05 81 3a 58 83 c0 03 74 ?? 81 3a 58 ff 30 60 74}  //weight: 3, accuracy: Low
        $x_2_3 = {66 81 38 28 0a 0f 85 ?? ?? ?? 00 6a 13 59 33 c0 8d 7d 98 f3 ab}  //weight: 2, accuracy: Low
        $x_2_4 = {66 8b 06 66 3d 41 00 72 ?? 66 3d 5a 00 77 ?? 83 c0 20 66 89 06 46 57 46 ff d3}  //weight: 2, accuracy: Low
        $x_1_5 = {0f b7 00 3d 93 08 00 00 0f 84 ?? ?? 00 00 3d 28 0a 00 00 74 ?? 3d ce 0e 00 00 0f 85 ?? ?? ?? 00 6a 27 bb 97 00}  //weight: 1, accuracy: Low
        $x_2_6 = {8b 46 60 89 5e 18 89 5e 1c 80 38 0e 75 ?? 8b 50 0c c7 46 1c 4c 06 00 00 b9 dc 05 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Rootkitdrv_CT_2147603128_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Rootkitdrv.CT"
        threat_id = "2147603128"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 3a 5c 31 30 2e 73 6f 6e 67 5c 63 6f 64 65 5c 63 6f 64 65 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 64 72 69 76 65 72 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c 61 75 74 6f 6c 69 76 65 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "%%systemroot%%\\system32\\Rundll32.exe %%systemroot%%\\system32\\%s.dll" ascii //weight: 1
        $x_1_3 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 25 25 73 79 73 74 65 6d 72 6f 6f 74 25 25 5c 73 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 25 25 73 79 73 74 65 6d 72 6f 6f 74 25 25 5c 73 79 73 74 65 6d 33 32 5c 25 73 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_4 = {5c 53 79 73 74 65 6d 52 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 25 77 73 2e 73 79 73 00 00 00 00 5c 53 79 73 74 65 6d 52 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 25 77 73 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = {75 73 65 72 69 6e 69 74 2e 65 78 65 00 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

