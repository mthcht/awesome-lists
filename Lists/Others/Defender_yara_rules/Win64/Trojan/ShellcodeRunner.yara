rule Trojan_Win64_ShellcodeRunner_BK_2147839582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.BK!MTB"
        threat_id = "2147839582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {01 d1 48 63 c9 44 0f b6 04 08 48 8b 44 24 08 0f b6 4c 24 06 48 c1 e1 02 48 01 c8 0f b6 4c 24 05 0f b6 14 08 44 31 c2 88 14 08 8a 44 24 05 04 01 88 44 24 05 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_DX_2147888945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.DX!MTB"
        threat_id = "2147888945"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c2 89 d0 c1 e0 02 01 d0 01 c0 01 d0 29 c1 89 ca 48 63 c2 0f b6 44 05 ?? 44 31 c0 89 c1 8b 45 fc 48 98 48 8d 15 [0-4] 88 0c 10 83 45 fc 01 8b 45 fc 3d fd 01 00 00 76}  //weight: 1, accuracy: Low
        $x_1_2 = {29 c2 89 d0 01 c0 01 d0 29 c1 89 ca 48 63 c2 0f b6 44 05 ?? 44 31 c0 89 c1 8b 45 fc 48 98 48 8d 15 [0-4] 88 0c 10 83 45 fc 01 8b 45 fc 3d fd 01 00 00 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_RDA_2147896469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.RDA!MTB"
        threat_id = "2147896469"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 44 24 08 48 63 0c 24 0f be 04 08 48 8b 4c 24 18 48 63 54 24 04 0f be 0c 11 31 c8 88 c2 48 8b 44 24 08 48 63 0c 24 88 14 08 8b 44 24 04 83 c0 01 89 44 24 04 8b 04 24 83 c0 01 89 04 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_AMMA_2147898696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.AMMA!MTB"
        threat_id = "2147898696"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 00 31 c6 89 f1 48 8b 15 ?? ?? ?? ?? 8b 45 fc 48 98 48 01 d0 89 ca 88 10 83 45 fc 01 8b 45 fc 48 63 d0 48 8b 05 ?? ?? ?? ?? 48 39 c2 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_BN_2147898712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.BN!MTB"
        threat_id = "2147898712"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 29 c2 44 6b c2 ?? 44 29 c0 89 c2 89 d0 83 c0 ?? 31 c1 48 8b 55 e0 8b 45 d4 48 98 88 0c 02 83 45 d4 01 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_BC_2147901504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.BC!MTB"
        threat_id = "2147901504"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c7 c0 60 00 00 00 65 48 8b 18 48 c7 c0 18 00 00 00 48 8b 1c 03 48 c7 c0 20 00 00 00 48 8b 1c 03 49 89 dc 48 8b 53 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_KAD_2147901627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.KAD!MTB"
        threat_id = "2147901627"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 89 d0 41 29 c0 41 8d 40 ?? 66 31 01 83 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_KAD_2147901627_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.KAD!MTB"
        threat_id = "2147901627"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 01 d0 44 0f b6 00 0f b6 0d ?? ?? 00 00 8b 55 ?? 48 8b 45 ?? 48 01 d0 44 89 c2 31 ca 88 10 83 45}  //weight: 20, accuracy: Low
        $x_10_2 = {48 98 48 8d 15 ?? ?? 00 00 88 0c 10 8b 45 ?? 48 98 48 8d 15 ?? ?? 00 00 0f b6 04 10 83 f0 ?? 89 c1 8b 45}  //weight: 10, accuracy: Low
        $x_5_3 = "First 16 bytes of decrypted shellcode:" ascii //weight: 5
        $x_5_4 = "Shellcode executed" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ShellcodeRunner_GPC_2147903401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.GPC!MTB"
        threat_id = "2147903401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "4989f941ba129689e2ffd54883c42085c074b6668b074801c385" ascii //weight: 5
        $x_5_2 = "4c4242524f57534552" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_GPE_2147903495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.GPE!MTB"
        threat_id = "2147903495"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4c 89 ca 49 f7 d9 49 c1 f9 3f 41 83 e1 10 48 8b 74 24 48 4c 01 ce 48 8b 78 18 48 89 d8 48 8b 5c 24 58 48 8b 4c 24 38 49 89 c8 49 89 d1 48 89 fa 48 89 cf}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_GPF_2147903496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.GPF!MTB"
        threat_id = "2147903496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ZmZmYzNDM3MmUzMT" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_GPD_2147903871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.GPD!MTB"
        threat_id = "2147903871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 74 24 40 48 8d 56 f0 48 89 54 24 40 48 f7 da 48 c1 fa 3f 83 e2 10 48 8b 4c 24 48 48 01 ca 48 89 54 24 48 90 48 8b 5c 24 50 41 b8 01 00 00 00 48 8b 44 24 60}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_ASDF_2147904263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.ASDF!MTB"
        threat_id = "2147904263"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 33 e4 48 89 44 24 ?? 44 89 a4 24 c4 00 00 00 49 8b d6 44 8b 45 ?? 48 8b cb 45 8d 4c 24 40 ff 15 ?? ?? ?? 00 48 8b 05}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 8b cd 44 89 64 24 28 45 33 c0 33 d2 48 89 74 24 20 48 8b cb ff 15 ?? ?? ?? 00 48 85 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_CL_2147905955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.CL!MTB"
        threat_id = "2147905955"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 00 31 c6 89 f1 48 8b 15 ?? ?? ?? 00 8b 45 fc 48 98 48 01 d0}  //weight: 2, accuracy: Low
        $x_2_2 = {31 c1 48 8b 55 ?? 8b 45 ?? 48 98 88 0c 02 83 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_CK_2147906191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.CK!MTB"
        threat_id = "2147906191"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 f7 e6 48 c1 ea 07 48 69 c2 ff 00 00 00 48 8b ce 48 2b c8 40 32 f9 40 30 bc 1d ?? ?? 00 00 48 ff c3 48 83 c6 ?? 48 81 fe}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_CM_2147906243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.CM!MTB"
        threat_id = "2147906243"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 39 d2 74 4e 8d 4b 01 0f b6 d9 0f b6 c9 8a 84 0c ?? ?? 00 00 46 8d 04 18 45 0f b6 d8 45 0f b6 c0 42 8a b4 04 ?? ?? 00 00 40 88 b4 0c ?? ?? 00 00 42 88 84 04 ?? ?? 00 00 02 84 0c ?? ?? 00 00 0f b6 c0 8a 84 04 ?? ?? 00 00 41 30 04 11 48 ff c2 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_MKV_2147906248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.MKV!MTB"
        threat_id = "2147906248"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c0 4c 8d 0d ?? ?? ?? ?? 4c 2b c8 48 8b c8 66 ?? 41 0f b6 14 09 48 8d 49 01 80 ea 06 41 ff c0 88 51 ff 41 83 f8 0c 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_RO_2147907142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.RO!MTB"
        threat_id = "2147907142"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\Users\\39392\\OneDrive\\Desktop\\Test1\\x64\\Debug\\Test1.pdb" ascii //weight: 5
        $x_2_2 = "%s%s%p%s%zd%s%d%s%s%s%s%s" ascii //weight: 2
        $x_1_3 = "Stack pointer corruption" ascii //weight: 1
        $x_1_4 = "Stack memory corruption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_KAF_2147907240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.KAF!MTB"
        threat_id = "2147907240"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c1 48 31 c0 8b 04 8e 41 51 4d 31 c9 49 ff c1 4d 85 c9 0f 84 ?? ?? ?? ?? 41 59 48 01 d8 4c 39 08}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 31 c0 4d 85 c0 0f 85 ?? ?? ?? ?? 49 ff c0 4d 85 c0 0f 84 ?? ?? ?? ?? 41 58 48 01 d8 4c 39 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_RP_2147908480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.RP!MTB"
        threat_id = "2147908480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 55 48 8d ac 24 90 fd ff ff 48 81 ec 70 03 00 00 41 b8 04 01 00 00 48 8d 55 60 33 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "qweasd321zxc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_RP_2147908480_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.RP!MTB"
        threat_id = "2147908480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 c9 48 c7 c2 ?? ?? 00 00 41 b8 00 10 00 00 44 8d 49 40 48 ff 15 ?? ?? ?? ?? e8 00 00 00 00 5e 48 81 c6 ?? ?? ?? ?? 48 89 c7 48 c7 ?? ?? ?? ?? 00 48 89 c2 90 a4 90 e2 fb ff e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_RP_2147908480_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.RP!MTB"
        threat_id = "2147908480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetOpenUrlW" ascii //weight: 1
        $x_1_2 = "InternetReadFile" ascii //weight: 1
        $x_1_3 = ".amazonaws.com/config/config.txt" wide //weight: 1
        $x_10_4 = "dick.exe" wide //weight: 10
        $x_1_5 = "afhost" wide //weight: 1
        $x_10_6 = "C:\\users\\public\\music\\ttmnq\\vbox\\" wide //weight: 10
        $x_1_7 = "C:\\users\\public\\pictures\\" wide //weight: 1
        $x_1_8 = "Failed to download file: " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_RP_2147908480_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.RP!MTB"
        threat_id = "2147908480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InternetOpenUrlW" ascii //weight: 1
        $x_1_2 = "InternetReadFile" ascii //weight: 1
        $x_1_3 = {2e 00 73 00 33 00 2e 00 61 00 70 00 2d 00 65 00 61 00 73 00 74 00 2d 00 31 00 2e 00 61 00 6d 00 61 00 7a 00 6f 00 6e 00 61 00 77 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-16] 2f 00 [0-16] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_10_4 = "dick.exe" wide //weight: 10
        $x_10_5 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 2f 6d 69 6e 20 43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c ?? ?? ?? ?? ?? ?? ?? 5c [0-16] 5c 64 6f 77 6e 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_6 = "steam_api64.dll" wide //weight: 1
        $x_1_7 = "afhost" wide //weight: 1
        $x_10_8 = "C:\\users\\public\\music\\ttmnq\\vbox\\" wide //weight: 10
        $x_1_9 = "C:\\users\\public\\pictures\\" wide //weight: 1
        $x_1_10 = "File downloaded successfully to" wide //weight: 1
        $x_1_11 = "Failed to download file: " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ShellcodeRunner_CCID_2147908511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.CCID!MTB"
        threat_id = "2147908511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 04 00 00 00 00 41 b9 40 00 00 00 41 b8 00 10 00 00 ba 01 00 00 00 33 c9 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_AG_2147910345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.AG!MTB"
        threat_id = "2147910345"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 44 05 ?? 89 c2 8b 85 ?? ?? 00 00 48 98 0f b6 84 05 ?? ?? 00 00 31 d0 89 c2 8b 85 ?? ?? 00 00 48 98 88 54 05 ?? 83 85 ?? ?? 00 00 01 83 85 ?? ?? 00 00 01 8b 85 ?? ?? 00 00 3b 85}  //weight: 4, accuracy: Low
        $x_4_2 = {0f b6 44 05 ?? 89 c2 8b 85 ?? ?? 00 00 48 98 0f b6 44 05 ?? 31 d0 89 c2 8b 85 ?? ?? 00 00 48 98 88 54 05 ?? 83 85 ?? ?? 00 00 01 83 85 ?? ?? 00 00 01 8b 85 ?? ?? 00 00 3b 85}  //weight: 4, accuracy: Low
        $x_1_3 = {41 b9 40 00 00 00 41 b8 00 30 00 00 ba 7d 03 00 00 b9 00 00 00 00 48 8b 05 ?? ?? ?? 00 ff d0 48 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ShellcodeRunner_ADS_2147910789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.ADS!MTB"
        threat_id = "2147910789"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c8 8b c1 25 ad 58 3a ff c1 e0 07 33 c8 8b c1 25 8c df ff ff c1 e0 0f 33 c8 8b c1 c1 e8 12 33 c1 49 3b c5 0f 87 67 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_AH_2147911299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.AH!MTB"
        threat_id = "2147911299"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b f8 48 8b f1 b9 ?? ?? 00 00 f3 a4 41 b9 40 00 00 00 41 b8 00 30 00 00 ba ?? ?? 00 00 33 c9 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = "Shellcode is written to allocated memory!" ascii //weight: 2
        $x_1_3 = "msfhe byhlcodhShel1" ascii //weight: 1
        $x_1_4 = "heX  hlcodhShel1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_GPAX_2147915639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.GPAX!MTB"
        threat_id = "2147915639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BtrMEduPNfN.(*endpointList).StateTypeName" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_KGG_2147920136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.KGG!MTB"
        threat_id = "2147920136"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 2b d0 0f b6 08 88 0c 02 48 8d 40 01 49 83 e8 01 75 f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_CG_2147921475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.CG!MTB"
        threat_id = "2147921475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 c9 41 b8 ?? ?? ?? ?? 41 b9 40 00 00 00 e8 ?? ?? ?? ?? 48 85 c0 74 ?? 48 89 c6 48 8d 15 ?? ?? ?? ?? 41 b8 ?? ?? 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 c7 44 24 ?? 00 00 00 00 c7 44 24 ?? 00 00 00 00 31 c9 31 d2 49 89 f0 45 31 c9 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_EXP_2147921715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.EXP!MTB"
        threat_id = "2147921715"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 45 e4 20 48 8b 05 43 a0 04 00 48 89 05 0c a0 04 00 eb 65}  //weight: 1, accuracy: High
        $x_1_2 = {8b 05 8e a0 04 00 48 8b 0d bb a0 04 00 31 04 31 48 83 c6 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_HMM_2147921722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.HMM!MTB"
        threat_id = "2147921722"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 08 80 f1 03 88 08 44 0f b6 c1 f6 c2 01 75 07 41 80 f0 02 44 88 00 ff c2 48 ff c0 3b d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_HNB_2147921839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.HNB!MTB"
        threat_id = "2147921839"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 61 69 6c 65 64 20 69 6e 20 63 68 61 6e 67 69 6e 67 20 70 72 6f 74 65 63 74 69 6f 6e 20 28 25 75 29 [0-16] 46 61 69 6c 65 64 20 69 6e 20 63 68 61 6e 67 69 6e 67 20 70 72 6f 74 65 63 74 69 6f 6e 20 62 61 63 6b 20 28 25 75 29}  //weight: 2, accuracy: Low
        $x_1_2 = "FC-48-83-E4-F0-E8" ascii //weight: 1
        $x_1_3 = "C0-00-00-00-41-51" ascii //weight: 1
        $x_1_4 = "NtCreateThreadEx Hooked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ShellcodeRunner_GM_2147922488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.GM!MTB"
        threat_id = "2147922488"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.xorDecrypt" ascii //weight: 2
        $x_2_2 = "main.xorEncrypt" ascii //weight: 2
        $x_2_3 = "main.generateKey" ascii //weight: 2
        $x_1_4 = "main.base64Decode" ascii //weight: 1
        $x_1_5 = "main.decryptAES" ascii //weight: 1
        $x_2_6 = "main.downloadData" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ShellcodeRunner_RPA_2147926892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.RPA!MTB"
        threat_id = "2147926892"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8d 45 f0 49 89 c1 48 8d 45 f8 49 89 c0 48 b8 7e 13 00 00 00 00 00 00 49 89 c3 48 8d 05 3c 13 00 00 49 89 c2 4c 89 d1 4c 89 da}  //weight: 10, accuracy: High
        $x_1_2 = {b8 00 30 00 00 48 89 44 24 20 48 8d 45 d8 49 89 c1 48 b8 00 00 00 00 00 00 00 00 49 89 c0 48 8d 45 e0 49 89 c3 48 8b 45 e8 49 89 c2 4c 89 d1 4c 89 da 4c 8b 1d 04 80 03 00 41 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_RPA_2147926892_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.RPA!MTB"
        threat_id = "2147926892"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 74 65 78 74 00 00 00 e6 6a 0c 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 64 61 74 61 00 00 34 18 02 00 00 80 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 34 89 00 00 00 a0 0e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 70 64 61 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_CCJR_2147927756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.CCJR!MTB"
        threat_id = "2147927756"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 4d e0 48 8d 45 c0 48 89 44 24 28 45 33 c9 45 33 c0 48 89 5c 24 20 33 d2 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {4c 8d 4d d0 ba 20 f2 08 00 41 b8 40 00 00 00 48 8b cb ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_MAZ_2147933870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.MAZ!MTB"
        threat_id = "2147933870"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 41 0f b6 c0 41 c0 e0 02 48 f7 f1 41 02 d0 02 d1 30 14 19 48 ff c1 48 3b cf 0f 82 7a ff ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_CLZ_2147934086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.CLZ!MTB"
        threat_id = "2147934086"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 4d 63 c2 4d 3b c1 48 8d 49 ?? 48 0f 45 d0 0f b6 04 1a 30 41 ff 33 c0 4d 3b c1 41 0f 45 c2 44 8d 50 01 48 8d 42 01 49 83 eb 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_PKZ_2147935244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.PKZ!MTB"
        threat_id = "2147935244"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "explorer.exe" wide //weight: 2
        $x_2_2 = "Allocate memory Success" ascii //weight: 2
        $x_2_3 = "Failed to write shellcode to memory" ascii //weight: 2
        $x_2_4 = "Inject successfully" ascii //weight: 2
        $x_1_5 = "Got handle to thread" ascii //weight: 1
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_7 = "Process32FirstW" ascii //weight: 1
        $x_1_8 = "GlobalMemoryStatusEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_ZIN_2147935851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.ZIN!MTB"
        threat_id = "2147935851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {31 c0 48 8b 7c 24 50 48 8b 94 24 88 00 00 00 4c 8b 84 24 d0 00 00 00 4c 8b 8c 24 c8 00 00 00 48 39 c5 74 ?? 48 83 f8 10 0f 84 ?? ?? ?? ?? 41 8a 0c 01 41 30 0c 02 48 ff c0 eb e4 49 83 f8 f0 0f 84}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_A_2147936267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.A!MTB"
        threat_id = "2147936267"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 2d b7 0d 00 00 48 8d be 00 f0 ff ff bb 00 10 00 00 50 49 89 e1 41 b8 04 00 00 00 48 89 da 48 89 f9 48 83 ec 20 ff d5 48 8d 87 af 01 00 00 80 20 7f 80 60 28 7f 4c 8d 4c 24 20 4d 8b 01 48 89 da 48 89 f9 ff d5}  //weight: 2, accuracy: High
        $x_2_2 = {53 56 57 55 48 8d 35 aa ef c0 ff 48 8d be db 0f f1 ff 48 8d 87 9c 41 4d 00 ff 30 c7 00 5c 24 97 9c 50 57 31 db 31 c9 48 83 cd ff e8 50 00 00 00 01 db 74 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_B_2147936273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.B!MTB"
        threat_id = "2147936273"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 fc 48 8b 45 f0 41 b8 23 00 00 00 48 89 c1 e8 ?? ?? ff ff 48 89 45 e8 e8 ?? ?? 00 00 48 98 48 89 45 e0 48 8b 45 e0 48 89 c2 48 83 ea 01 48 89 55 d8 48 83 c0 0f 48 c1 e8 04 48 c1 e0 04 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_NR_2147936333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.NR!MTB"
        threat_id = "2147936333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {84 00 c6 80 b0 22 00 00 00 83 3d 0d c3 1c 00 00 0f 85 fc 02 00 00 83 b8 70 22 00 00 00 74 14 48 89 44 24 30 e8 74 cf ff ff}  //weight: 3, accuracy: High
        $x_2_2 = {48 8b 4c 24 20 48 8b 51 30 48 8b 9a a0 00 00 00 48 8d 05 b1 ff 21 00 e8 ec 24 fe ff 48 85 c0 0f 95 c1 0f b6 54 24 15 09 d1 88 4c 24 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_NR_2147936333_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.NR!MTB"
        threat_id = "2147936333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 45 d0 41 b9 ?? 00 00 00 49 89 d0 ba ?? ?? 00 00 48 89 c1 e8 ?? ?? ff ff 48 8b 85 ?? ?? 00 00 48 8d 15 ?? ?? 00 00 48 89 c1 48 8b 05}  //weight: 2, accuracy: Low
        $x_1_2 = {ff d0 48 89 85 ?? ?? 00 00 4c 8b 95 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 c7 44 24 ?? ?? 00 00 00 41 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_SMW_2147936578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.SMW!MTB"
        threat_id = "2147936578"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b c2 88 44 24 4e 0f b6 44 24 4e 0f b6 84 04 20 01 00 00 88 44 24 4f 8b 44 24 54 0f b6 4c 24 4f 48 8b 94 24 88 00 00 00 0f b6 04 02 33 c1 8b 4c 24 54 48 8b 94 24 88 00 00 00 88 04 0a}  //weight: 2, accuracy: High
        $x_3_2 = {48 33 c0 4d 33 d2 49 83 c2 60 65 49 8b 02 48 8b 40 18 48 8b 40 10 48 8b 00 48 8b 00 48 8b 40 30}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_MLZ_2147936781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.MLZ!MTB"
        threat_id = "2147936781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 10 00 4c 8d 4c 24 20 ba b1 01 00 00 41 0f 11 00 0f 10 48 10 41 0f 11 48 10 0f 10 40 20 41 0f 11 40 20 0f b6 48 ?? 41 88 48 30 41 b8 20 00 00 00 48 8b cb ff 15 8a 1e 00 00 48 8d 0d 13 21 00 00 e8 ?? ?? ?? ?? ff d3 33 c0 48 8b 4c 24 28 48 33 cc e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_TPZ_2147936968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.TPZ!MTB"
        threat_id = "2147936968"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b 8d 00 01 00 00 48 03 c8 48 8b c1 0f b6 00 0f b6 8d ?? ?? ?? ?? 33 c1 48 8b 4d 08 48 8b 95 00 01 00 00 48 03 d1 48 8b ca 88 01 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_RPD_2147939684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.RPD!MTB"
        threat_id = "2147939684"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "65"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Failed to take process snapshot!" ascii //weight: 10
        $x_10_2 = "Failed to retrieve first process!" ascii //weight: 10
        $x_10_3 = "Ven_sign" ascii //weight: 10
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_10_5 = "chonging" wide //weight: 10
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" wide //weight: 1
        $x_1_7 = "Startup" wide //weight: 1
        $x_10_8 = "%ProgramData%\\Venlnk" wide //weight: 10
        $x_1_9 = "Process is running, exiting..." wide //weight: 1
        $x_1_10 = "\\static.ini" wide //weight: 1
        $x_10_11 = "OpenAi_Service" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_RPS_2147939685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.RPS!MTB"
        threat_id = "2147939685"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Task created successfully!" ascii //weight: 1
        $x_1_2 = "Failed to take process snapshot!" ascii //weight: 1
        $x_1_3 = "Failed to retrieve first process!" ascii //weight: 1
        $x_10_4 = "Ven_sign" ascii //weight: 10
        $x_1_5 = "Failed to open registry key." wide //weight: 1
        $x_1_6 = "Failed to read registry value." wide //weight: 1
        $x_10_7 = "Software\\DeepSer" wide //weight: 10
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_10_9 = "OpenAi_Service" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_AHB_2147941646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.AHB!MTB"
        threat_id = "2147941646"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 85 88 00 00 00 48 8d 55 28 48 8d 4d 58 ff 95 88 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = {c7 45 04 00 00 00 00 8b 85 ?? ?? 00 00 89 45 28 8b 85 98 01 00 00 89 45 2c 48 8b 85 90 01 00 00}  //weight: 5, accuracy: Low
        $x_1_3 = {73 50 61 79 6c 6f 61 64 53 69 7a 65 00 00 00 00 70 50 61 79 6c 6f 61 64 44 61 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_ALV_2147942873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.ALV!MTB"
        threat_id = "2147942873"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 ff c1 49 63 c9 48 8d 95 ?? ?? ?? ?? 48 03 d1 0f b6 0a 41 88 0b 44 88 02 45 02 03 41 0f b6 d0 44 0f b6 84 15 ?? ?? ?? ?? 45 30 02 49 ff c2 48 83 eb 01 75 92}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_C_2147945037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.C!MTB"
        threat_id = "2147945037"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 0c 07 30 08 48 8d 40 01 48 83 ea 01 75 ?? eb ?? f3 0f 6f 03 f3 0f 6f 0e 0f 57 c8 f3 0f 7f 0b 48 83 c3 ?? 49 83 c6 ?? 48 83 ef ?? 48 83 c5 ?? 0f 11 36 49 83 ef}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_DEL_2147945717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.DEL!MTB"
        threat_id = "2147945717"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 33 41 0f b6 c0 41 ff c0 2a c1 04 38 41 30 41 ff 41 83 f8 0e 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_SXA_2147945954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.SXA!MTB"
        threat_id = "2147945954"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff d0 48 89 45 f8 48 83 7d f8 00 75 07 b8 01 00 00 00 eb 1c 8b 55 ec 48 8b 45 f8 89 10 48 8b 45 f8 48 89 45 f0 48 8b 45 f0 ff d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_MZZ_2147946990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.MZZ!MTB"
        threat_id = "2147946990"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 00 88 04 19 48 ff c1 48 ff ca 48 3b ce 72 ?? 49 8b cd 8d 41 01 30 04 19 48 ff c1 48 3b ce 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_MVC_2147947168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.MVC!MTB"
        threat_id = "2147947168"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 8b c0 33 d2 48 8b c3 48 ff c3 48 f7 f6 0f b6 0c 2a 41 30 08 48 8b cf e8 ?? ?? ?? ?? 48 3b d8 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_BOF_2147947428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.BOF!MTB"
        threat_id = "2147947428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 2d 70 08 00 00 0f b6 00 48 8b 95 08 08 00 00 48 89 d1 48 0f af 8d e8 07 00 00 48 8b 95 00 08 00 00 48 01 d1 48 8b 95 d0 07 00 00 48 01 ca 32 85 ff 07 00 00 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_PSG_2147947445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.PSG!MTB"
        threat_id = "2147947445"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 b7 48 8b 85 d8 07 00 00 48 89 85 c8 07 00 00 48 8b 85 c8 07 00 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_PCP_2147947501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.PCP!MTB"
        threat_id = "2147947501"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 85 fc 0f 00 00 0f b6 44 05 a0 32 85 0f 10 00 00 89 c2 48 8b 85 00 10 00 00 88 10 8b 85 ?? ?? ?? ?? d1 e8 00 85 0f 10 00 00 48 83 85 00 10 00 00 01 83 85 fc 0f 00 00 02 8b 85 fc 0f 00 00 3b 85 ec 0f 00 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_AHC_2147947688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.AHC!MTB"
        threat_id = "2147947688"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {b9 04 01 00 00 48 89 c7 48 89 d6 f3 48 a5 c6 85 ?? 07 00 00 42 48 c7 85 ?? 07 00 00 20 08 00 00 48 8b 85 ?? 07 00 00 41 b9 40 00 00 00 41 b8 00 30 00 00}  //weight: 20, accuracy: Low
        $x_20_2 = {b9 04 01 00 00 48 89 c7 48 89 d6 f3 48 a5 48 b8 01 02 03 04 05 06 07 08 48 ba 09 0a 0b 0c 0d 0e 0f 10}  //weight: 20, accuracy: High
        $x_30_3 = {48 01 d0 0f b6 00 48 8b 8d ?? 07 00 00 48 8b 95 ?? 07 00 00 48 01 ca 32 85 ?? 07 00 00 88 02}  //weight: 30, accuracy: Low
        $x_30_4 = {8b 85 7c 08 00 00 48 98 0f b6 44 05 30 32 85 57 08 00 00 89 c2 8b 85 7c 08 00 00 48 98 88 54 05 30}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ShellcodeRunner_MLD_2147947764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.MLD!MTB"
        threat_id = "2147947764"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 d0 0f b6 c0 48 98 0f b6 44 05 a0 88 85 fe 10 00 00 48 8d 95 d0 08 00 00 48 8b 85 ?? 11 00 00 48 01 d0 0f b6 00 32 85 fe 10 00 00 48 8d 8d a0 00 00 00 48 8b 95 ?? 11 00 00 48 01 ca 88 02 48 83 85 ?? 11 00 00 01 48 81 bd 38 11 00 00 1f 08 00 00 0f 86}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_GFN_2147948148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.GFN!MTB"
        threat_id = "2147948148"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 3a 0f b6 ?? 2a c2 04 32 41 30 00 ff c1 4d 8d 40 01 83 f9 0f 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_ZZI_2147948591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.ZZI!MTB"
        threat_id = "2147948591"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 98 0f b6 44 05 80 88 85 ?? 00 00 00 48 8b 95 b0 00 00 00 48 8b 85 ?? 00 00 00 48 01 d0 0f b6 00 48 8b 8d b0 00 00 00 48 8b 95 88 00 00 00 48 01 ca 32 85 86 00 00 00 ?? 02 48 83 85 88 00 00 00 01 48 8b 85 ?? 00 00 00 48 3b 85 b8 00 00 00 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_CB_2147949573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.CB!MTB"
        threat_id = "2147949573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ba 5c 00 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 83 bd ?? ?? ?? ?? ?? 74 ?? 48 8b 85 ?? ?? ?? ?? c6 00 00 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 85 b8 00 00 00 48 8d 55 b0 48 8b 85 b8 00 00 00 49 89 d1 4c 8d 05 b8 39 00 00 ba 04 01 00 00 48 89 c1}  //weight: 3, accuracy: Low
        $x_2_2 = {41 b9 40 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0 48 89 45 ?? 8b 45 ?? 48 63 c8 48 8b 55 ?? 48 8b 45 ?? 49 89 c8 48 89 c1 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_CA_2147949807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.CA!MTB"
        threat_id = "2147949807"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6d 68 71 66 c7 44 24 ?? 64 68 70 6f c7 44 24 ?? 64 78 6a 71 c7 44 24 ?? 69 62 69 71 c7 44 24 ?? 6f 77 71 69 c7 44 24 ?? 6a 68 69 72 c7 44 24 ?? 70 62 63 64 44 88 7c 24}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8d 55 b0 c7 45 ?? ?? ?? ?? ?? 48 8b cf ff 15 ?? ?? ?? ?? 48 8b cf}  //weight: 2, accuracy: Low
        $x_2_3 = {4c 89 65 00 48 0f ba f0 ?? 48 0f ba e8 ?? 48 89 45 ?? ff 15 ?? ?? ?? ?? 8b d8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_LM_2147950653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.LM!MTB"
        threat_id = "2147950653"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 53 48 83 ec 38 48 8d ac 24 80 00 00 00 48 89 4d d0 48 89 55 d8 48 c7 45 a8 00 00 00 00 48 8b 45 a8 48 3b 45 d8 73 ?? 48 8b 55 d0 48 8b 45 a8 48 01 d0 0f b6 00 0f b6 c0 48 8b 4d d0 48 8b 55 a8 48 8d 1c 11 89 c1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_PAHS_2147952085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.PAHS!MTB"
        threat_id = "2147952085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 55 e8 48 8b 45 b8 48 01 d0 0f b6 10 4c 8b 45 f0 8b 45 ec 8d 48 01 89 4d ec 89 c0 4c 01 c0 88 10 83 45 e8 01 8b 45 a4 39 45 e8 72}  //weight: 3, accuracy: High
        $x_2_2 = {48 8d 45 e0 41 b9 00 00 00 00 49 89 c0 ba 82 23 00 00 48 8d 05 28 4b 01 00 48 89 c1 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_MPX_2147952286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.MPX!MTB"
        threat_id = "2147952286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 8b c2 49 f7 e0 48 c1 ea 03 48 8d 04 d2 49 8b c8 48 2b c8 0f b6 84 0d ?? ?? ?? ?? 43 30 04 01 49 ff c0 4c 3b c6 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_MXS_2147952521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.MXS!MTB"
        threat_id = "2147952521"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 e2 1f 0f b6 14 0a 41 30 54 06 fe 41 83 e0 1f 41 0f b6 14 08 41 30 54 06 ?? 89 c2 83 e2 1f 0f b6 14 0a 41 30 14 06 48 83 c0 03 48 3d 8e 00 0a 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_LMA_2147952617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.LMA!MTB"
        threat_id = "2147952617"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {4d 8b c7 49 8b d6 [0-6] 00 49 83 f8 ?? 48 8d 52 01 49 8b cf 49 0f 45 c8 41 ff c1 0f b6 84 0d 18 01 00 00 4c 8d 41 01 30 42 ff 49 63 c1 48 3b c7}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_ARA_2147952670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.ARA!MTB"
        threat_id = "2147952670"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b d3 48 8b cf e8 ?? ?? ?? ?? 4c 8b c0 33 d2 48 8b c3 48 ff c3 48 f7 f6 [0-2] 0c 2a 41 30 08 48 8b cf e8 ?? ?? ?? ?? 48 3b d8 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_SRH_2147953772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.SRH!MTB"
        threat_id = "2147953772"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 34 06 31 f2 88 14 0b 48 ff c1 48 89 d8 48 81 f9 ?? 03 00 00 7d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeRunner_AHF_2147953786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunner.AHF!MTB"
        threat_id = "2147953786"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {50 48 f7 d0 48 29 c5 58 48 83 ed ?? 48 8b c6 48 2b c1 50 48 f7 d0 48 29 c7 58 48 83 ef ?? 49 f7 d8 4c 89 84}  //weight: 20, accuracy: Low
        $x_30_2 = {44 0f b6 44 24 ?? 0f b6 44 24 ?? 66 41 c1 e0 ?? 66 44 0b c0 66 44 89 06 48 8b cf 48 8b 07 eb}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

