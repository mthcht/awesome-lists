rule Trojan_Win32_FakeSysdef_155638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 56 c7 45 fc 68 83 01 00 8b 45 fc 8b 4d fc 83 e9 01 89 4d fc 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 be 08 62 40 00 8b 36 6a 43 ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 cc fa 0c 00 00 c7 45 e4 00 00 00 00 c7 45 e8 d4 81 01 00 c7 45 dc 0b 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 56 c7 45 fc 58 75 01 00 8b 45 fc 8b 4d fc 83 e9 01 89 4d fc 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {be 58 62 40 00 6a 02 8b 36 68 00 70 40 00 68 90 77 40 00 4e ff d6 83 c4 0c}  //weight: 1, accuracy: High
        $x_1_3 = {c7 85 c4 fe ff ff 6d 6f 10 00 c7 85 dc fe ff ff d9 e2 12 00 c7 85 e0 fe ff ff 81 77 09 00 c7 85 d4 fe ff ff 6e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HDDRepair module activ" wide //weight: 1
        $x_1_2 = "Run Defragmentation" wide //weight: 1
        $x_1_3 = "activation code" wide //weight: 1
        $x_1_4 = ".lic" wide //weight: 1
        $x_1_5 = "for your purchase, %s" wide //weight: 1
        $x_1_6 = "PC is in danger" wide //weight: 1
        $x_1_7 = "scan your hard driv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ca 8b 55 08 03 55 fc 88 0a 0f be 45 fb 05 23 cb 12 00 0f af 45 f0 89 45 f0 8b 4d 08 03 4d fc 8b 55 08 03 55 fc 8a 02 88 41 ff eb b0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 95 d8 fe ff ff 52 8b 45 f0 50 68 ?? ?? ?? ?? ff 15 ?? ?? 40 00 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a4 61 83 c0 00 ff e0 60}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 ec 00 00 00 00 c7 45 f0 56 69 72 74 c7 45 f4 75 61 6c 50 c7 45 f8 72 6f 74 65 66 c7 45 fc 63 74 c6 45 fe 00}  //weight: 1, accuracy: High
        $x_1_3 = {e8 00 00 00 00 59 66 83 c9 ff 66 41 66 8b 11 66 81 f2 ?? ?? 66 81 fa ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_4 = {e8 00 00 00 00 59 81 e1 00 f0 ff ff 66 81 39 4d 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "83a5f83b-5aa7-4fa7-bbf5-63829add296e" wide //weight: 1
        $x_1_2 = {8b 44 24 08 56 8d 54 24 08 57 8b 3d ?? ?? ?? ?? 52 53 53 6a 19 50 ff d7 85 c0 75 ?? ff 15 ?? ?? ?? ?? 83 f8 7a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rootkit__" wide //weight: 1
        $x_1_2 = {00 00 00 00 2e 00 6c 00 69 00 63 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 59 8d 8c 24 ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 68 20 bf 02 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {51 52 68 02 00 00 80 e8 ?? ?? ?? ?? 8d 44 24 14 50 e8 ?? ?? ?? ?? 83 f8 06 72}  //weight: 1, accuracy: Low
        $x_1_5 = {50 51 68 01 00 00 80 c7 44 ?? ?? 0a 02 00 00 e8 ?? ?? ?? ?? 85 c0 74 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 19 51 ff d7 85 c0 74 ?? 8b 16 52 ff 15 ?? ?? ?? ?? 8a 00 8b 0e fe c8 25 ff 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 19 50 ff d7 85 c0 75 8b 16 52 ff 15 ?? ?? ?? ?? 8a 00 8b 0e fe c8 25 ff 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {2b de 66 8b 04 33 55 66 33 44 24 ?? 47 66 89 06 83 c6 02 ff 15 ?? ?? ?? ?? 3b f8 7c e5}  //weight: 1, accuracy: Low
        $x_1_4 = {52 50 68 02 00 00 80 e8 ?? ?? ?? ?? 83 c4 ?? e8 ?? ?? ?? ?? b9 1f 00 00 00 33 c0 8d bc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeSysdef_155638_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "stats&affid=%s&subid=%s&i" wide //weight: 2
        $x_1_2 = "hard drive error occurred" wide //weight: 1
        $x_1_3 = "Processing Message 0x0000013 Parameters" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeSysdef_155638_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\fcrypt\\Release\\S\\s_high.pdb" ascii //weight: 1
        $x_1_2 = {3a 5c 73 72 63 5c [0-8] 5c 52 65 6c 65 61 73 65 5c 53 5c}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 02 8b c8 81 e1 ff 0f 00 00 03 4c 24 10 4e c1 e8 0c 89 74 24 14 83 f8 03 75 07}  //weight: 1, accuracy: High
        $x_1_4 = {8b df 2b da 8d 9b 00 00 00 00 8b 50 04 8b 08 2b f2 83 c0 08 83 c2 f8 50 d1 ea 03 cf 52 51 e8 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 07 8a c8 80 e9 ?? 80 f9 ?? 77 ?? 66 0f be d0 66 83 c2 20 0f b7 f2 eb ?? 66 98 0f b7 f0 8a 03 8a ?? 80 e9 ?? 80 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 37 99 f7 7d 10 8b 45 0c 8a 04 02 02 01 00 45 0b 0f b6 45 0b}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 02 75 2a 8d 85 00 e0 ff ff 6a 04 50 ff 34 b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 85 00 f0 ff ff 6a 04 50 ff 34 b5 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_3 = "recommended that you restart the system" wide //weight: 1
        $x_1_4 = {61 64 77 3a 20 74 65 72 6d 69 6e 61 74 65 20 25 6c 75 20 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 58 1b 00 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 08 01 00 00 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 33 ff 8d b5 ?? ?? ?? ?? 6a 02 57 68 44 23 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b de 66 8b 04 33 ff 75 ?? 66 33 45 ?? ff 45 ?? 66 89 ?? 46 46 ff d7 39 45 ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 40 7e 05 00 eb 05 68 a0 bb 0d 00 ff 15 ?? ?? ?? ?? 39 35 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = "Install %s software (recomended)" wide //weight: 1
        $x_1_4 = "%s is professional software toolkit designed to detect, identify and fix hardware memory related problems" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "avoid data loss it is highly recommended to run System Repair Wizard" wide //weight: 1
        $x_1_2 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 20 43 6f 72 72 75 70 74 20 44 69 73 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = "%s%s/%s?p=%s&aid=%s&sid=%s&hash=%s&product=%s" wide //weight: 1
        $x_1_4 = "Checking S.M.A.R.T. attributes..." wide //weight: 1
        $x_1_5 = "physical resources of this disk have been exhausted. The device is unreachable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b de 66 8b 04 33 ff 75 ?? 66 33 45 ?? ff 45 ?? 66 89 ?? 46 46 ff d7 39 45 ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "__exe_url__" wide //weight: 1
        $x_1_3 = "__exe_download__" wide //weight: 1
        $x_1_4 = "detected a problem with one or more installed IDE / SATA hard disks" wide //weight: 1
        $x_1_5 = ".php?type=stats&affid=%s&subid=%s&version=%s&installok" wide //weight: 1
        $x_1_6 = "[Your disk is in a critical state. Click here for more" wide //weight: 1
        $x_1_7 = "%s\\%s_License.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 00 78 00 65 00 20 00 66 00 69 00 6c 00 65 00 20 00 69 00 73 00 20 00 63 00 6f 00 72 00 72 00 75 00 70 00 74 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 63 00 61 00 6e 00 27 00 74 00 20 00 62 00 65 00 20 00 72 00 75 00 6e 00 2e 00 20 00 48 00 61 00 72 00 64 00 20 00 64 00 72 00 69 00 76 00 65 00 20 00 73 00 63 00 61 00 6e 00 20 00 72 00 65 00 71 00 75 00 69 00 72 00 65 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 00 6c 00 69 00 63 00 6b 00 20 00 25 00 74 00 62 00 5b 00 22 00 41 00 6c 00 6c 00 6f 00 77 00 22 00 5d 00 20 00 77 00 68 00 65 00 6e 00 20 00 55 00 41 00 43 00 20 00 73 00 63 00 72 00 65 00 65 00 6e 00 20 00 61 00 70 00 70 00 65 00 61 00 72 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "DefragHDDRepair module activation required to enable" wide //weight: 1
        $x_1_4 = {25 00 73 00 20 00 70 00 65 00 72 00 66 00 6f 00 72 00 6d 00 61 00 6e 00 63 00 65 00 20 00 69 00 73 00 73 00 75 00 65 00 73 00 20 00 66 00 6f 00 75 00 6e 00 64 00 2e 00 20 00 43 00 6c 00 69 00 63 00 6b 00 20 00 25 00 25 00 74 00 6c 00 5b 00 68 00 65 00 72 00 65 00 5d 00 20 00 74 00 6f 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 70 00 65 00 72 00 66 00 6f 00 6d 00 61 00 6e 00 63 00 65 00 20 00 26 00 20 00 73 00 74 00 61 00 62 00 69 00 6c 00 69 00 74 00 79 00 20 00 6f 00 70 00 74 00 69 00 6d 00 69 00 7a 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "readdatagateway.php?type=stats&affid=%s" ascii //weight: 1
        $x_1_6 = "DefragHDDRepair tool can fix detected hard drive" wide //weight: 1
        $x_1_7 = {85 c0 7e 0c 80 7c 04 18 5c 74 05 48 85 c0 7f f4 8b 94 24 ?? ?? ?? ?? 8d 44 04 19 52 50 ff 15 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_FakeSysdef_155638_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSysdef"
        threat_id = "155638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSysdef"
        severity = "173"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 65 00 66 00 72 00 61 00 67 00 6d 00 65 00 6e 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 00 75 00 6e 00 20 00 44 00 65 00 66 00 72 00 61 00 67 00 6d 00 65 00 6e 00 74 00 61 00 74 00 69 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {42 00 75 00 79 00 20 00 4e 00 6f 00 77 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 65 61 64 64 61 74 61 67 61 74 65 77 61 79 2e 70 68 70 3f 74 79 70 65 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 2f 25 73 2f 25 73 2d 64 69 72 65 63 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {72 00 6f 00 6f 00 74 00 6b 00 69 00 74 00 5f 00 5f 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {38 38 35 36 46 39 36 31 2d 33 34 30 41 2d 31 31 44 30 2d 41 39 36 42 2d 30 30 43 30 34 46 44 37 30 35 41 32 00}  //weight: 1, accuracy: High
        $x_1_9 = {38 33 61 35 66 38 33 62 2d 35 61 61 37 2d 34 66 61 37 2d 62 62 66 35 2d 36 33 38 32 39 61 64 64 32 39 36 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {36 32 35 37 37 33 64 30 2d 31 65 62 35 2d 34 38 37 39 2d 38 33 32 32 2d 38 62 64 63 33 33 64 39 64 34 66 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {39 63 66 32 35 39 32 63 2d 31 38 33 32 2d 34 33 35 38 2d 61 30 66 63 2d 32 36 64 36 61 30 63 32 39 38 30 38 00}  //weight: 1, accuracy: High
        $x_1_12 = {64 38 62 62 35 39 31 30 2d 32 64 38 35 2d 34 38 39 62 2d 38 34 30 33 2d 38 30 33 65 64 32 35 65 37 33 62 63 00}  //weight: 1, accuracy: High
        $x_1_13 = {66 37 63 35 64 61 37 33 2d 62 34 61 35 2d 34 39 34 37 2d 38 66 34 30 2d 30 38 66 32 38 37 31 65 62 33 36 62 00}  //weight: 1, accuracy: High
        $x_1_14 = "searchfindfix.org" wide //weight: 1
        $x_1_15 = "searchmemory.org" wide //weight: 1
        $x_1_16 = ".lic" wide //weight: 1
        $x_1_17 = "?pid=%s&id=%s&subid=%s&guid=%s" wide //weight: 1
        $x_1_18 = "Hard drive clusters are partly damaged. Segment load failure" ascii //weight: 1
        $x_1_19 = "RAM memory reliability is extremely low. This problem may cause system failure" ascii //weight: 1
        $x_1_20 = "//%s/%s/%s-direct" wide //weight: 1
        $x_1_21 = ".php?type=stats&affid=%s&subid=%s" wide //weight: 1
        $x_1_22 = "Windows - Delayed Write Failed" wide //weight: 1
        $x_1_23 = "_exe_url__" wide //weight: 1
        $x_1_24 = "_exe_download__" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

