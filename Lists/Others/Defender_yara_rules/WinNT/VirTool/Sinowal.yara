rule VirTool_WinNT_Sinowal_A_2147599875_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sinowal.A"
        threat_id = "2147599875"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 c7 05 ?? ?? ?? 00 ?? ?? ?? 00 ff 25}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7c 24 0c 05 c7 05 ?? ?? ?? 00 ?? ?? ?? 00 ff 25}  //weight: 1, accuracy: Low
        $x_1_3 = {68 70 53 74 75 ff 74 24 08 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Sinowal_C_2147602533_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sinowal.C"
        threat_id = "2147602533"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 ff 25 ?? ?? 01 00 [0-7] ff 25 ?? ?? 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7c 24 0c 05 ff 25 ?? ?? 01 00 [0-7] ff 25 ?? ?? 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 70 53 74 75 ff 74 24 08 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Sinowal_D_2147606894_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sinowal.D"
        threat_id = "2147606894"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f6 9c 50}  //weight: 1, accuracy: High
        $x_1_2 = {83 7c 24 0c 05 9c 50}  //weight: 1, accuracy: High
        $x_1_3 = {68 70 53 74 75 ff 74 24 08 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Sinowal_E_2147623421_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sinowal.E"
        threat_id = "2147623421"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 01 45 fc 8b 06 8b 7d f4 9c [0-11] 83 cf 00 3b fe 5f 74}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 aa aa aa aa 8d 7d f0 ab 56 ff 75 fc ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Sinowal_F_2147624381_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sinowal.F"
        threat_id = "2147624381"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 38 02 00 c0 9c}  //weight: 1, accuracy: High
        $x_1_2 = {b8 00 04 00 04 9c}  //weight: 1, accuracy: High
        $x_1_3 = {3d 0b 01 00 00 9c}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 fc a1 eb d9 6e 9c}  //weight: 1, accuracy: High
        $x_1_5 = {c7 45 fc 05 00 00 00 9c [0-2] (50|2d|57)}  //weight: 1, accuracy: Low
        $x_1_6 = {0f 1f 40 00 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_WinNT_Sinowal_G_2147628675_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sinowal.G"
        threat_id = "2147628675"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ff 00 5f 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {83 fb 00 5b 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {83 fe 00 5e 0f 85}  //weight: 1, accuracy: High
        $x_1_4 = {bb 00 00 00 00 81 c3 ?? ?? ?? ?? 53}  //weight: 1, accuracy: Low
        $x_1_5 = {b9 00 00 00 00 81 c1 ?? ?? ?? ?? 51}  //weight: 1, accuracy: Low
        $x_1_6 = {24 83 c4 04 33 f6 81 c6 02 00 8b}  //weight: 1, accuracy: Low
        $x_6_7 = {38 02 00 c0 (eb|e9) 05 00 (b8|2d|bf)}  //weight: 6, accuracy: Low
        $x_1_8 = {8b 45 08 89 45 fc 66 c7 45 f0 18 00 66 c7 45 f2 1a 00 c7 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Sinowal_H_2147630216_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sinowal.H"
        threat_id = "2147630216"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff 75 10 ff 75 0c ff 55 fc}  //weight: 2, accuracy: High
        $x_1_2 = {50 90 90 58 2b}  //weight: 1, accuracy: High
        $x_1_3 = {57 90 90 5f 2b}  //weight: 1, accuracy: High
        $x_1_4 = {53 5b 2b db 81 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Sinowal_I_2147644814_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sinowal.I"
        threat_id = "2147644814"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 10 ff 75 0c ff 55 fc}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 fc 66 c7 45 f0 ?? ?? 66 81 45 f0 ?? ?? 66 c7 45 f2 ?? ?? 66 81 45 f2}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 38 25 ff 0f 00 00 75}  //weight: 1, accuracy: High
        $x_1_4 = {ff 75 0c 58 ff 50 04 ff 75 08 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_WinNT_Sinowal_J_2147646765_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sinowal.J"
        threat_id = "2147646765"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 10 ff 75 0c ff 55 fc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 05 cc 01 00 00 50}  //weight: 1, accuracy: High
        $x_1_3 = {83 7d 08 00 75 07 32 c0 e9 ?? ?? ?? ?? 8b 45 f0 0f b7 00 3d 4d 5a 00 00 74 07 32 c0 e9 ?? ?? ?? ?? 8b 45 f0 8b 4d 08 03 48 3c 89 4d ec 8b 45 ec 81 38 50 45 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Sinowal_K_2147680437_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sinowal.K"
        threat_id = "2147680437"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 3d 00 05 df ff 21 a1 00 ee 75 12}  //weight: 1, accuracy: High
        $x_1_2 = "\\Device\\HardDisk%i" wide //weight: 1
        $x_1_3 = {81 38 30 00 68 69 75 02 eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

