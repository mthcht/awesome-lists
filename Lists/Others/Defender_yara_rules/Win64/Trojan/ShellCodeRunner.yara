rule Trojan_Win64_ShellCodeRunner_ASR_2147907975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.ASR!MTB"
        threat_id = "2147907975"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b c2 0f b7 00 41 8b c8 c1 c9 08 41 ff c1 03 c8 41 8b c1 49 03 c2 44 33 c1 44 38 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_NS_2147914182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.NS!MTB"
        threat_id = "2147914182"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {65 4d 8b 36 4d 8b 36 48 8d 05 ?? ?? 06 00 48 89 04 24 e8 34 71 02 00 45 0f 57 ff 4c 8b 35}  //weight: 2, accuracy: Low
        $x_1_2 = {bb 00 00 01 00 0f 1f 00 e8 5b 95 04 00 eb 8d 48 89 7c 24 ?? b8 00 00 01 00 31 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_NS_2147914182_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.NS!MTB"
        threat_id = "2147914182"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 8b e8 45 33 c0 48 85 ed 74 4e 43 0f b7 34 44 49 3b f1 75 37 47 8b 5c 85 00 4d 03 da 33 ff eb 16 8b d7 8b c7 c1 e0 19 d3 ea}  //weight: 3, accuracy: High
        $x_2_2 = {45 84 ff 75 e2 3b 7c 24 40 75 07 41 8b 1c b6 49 03 da 49 ff c0 4c 3b c5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_NS_2147914182_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.NS!MTB"
        threat_id = "2147914182"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 05 7a 45 45 00 48 89 04 24 48 c7 44 24 08 ?? ?? ?? ?? 48 8b 44 24 30 48 89 44 24 ?? 48 c7 44 24 18 ?? ?? ?? ?? 48 c7 44 24 20}  //weight: 3, accuracy: Low
        $x_3_2 = {45 0f 57 ff 4c 8b 35 d0 5b 4e ?? 65 4d 8b 36 4d 8b 36 48 8b 44 24 ?? 48 8b 6c 24 38}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_NS_2147914182_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.NS!MTB"
        threat_id = "2147914182"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 32 f6 40 88 74 24 ?? e8 fe 03 00 00 8a d8 8b 0d 96 1a 02 00 83 f9 01 0f 84 23 01 00 00 85 c9 75 4a c7 05 7f 1a 02 00 ?? ?? ?? ?? 48 8d 15 e8 59 01 00 48 8d 0d a9 59 01 00}  //weight: 2, accuracy: Low
        $x_3_2 = {48 8d 05 d2 13 02 00 89 74 24 68 48 89 45 80 48 8d 05 b3 13 02 00 48 89 45 88 c7 44 24 78 ?? ?? ?? ?? e8 a2 f9 ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_AB_2147921615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.AB!MTB"
        threat_id = "2147921615"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 64 59 20 ef cf 79 da b8 1a ee 34 84 e7 33 2a 98 1c 78 94 73 50 62 dd 43 44 44 3a 90 63 7e 12 6f 4d 87 8b 51 32 2b db 8a 2d 8e 21 23 ef d6 7e af 07 5e 87 7f f5 48 65 18 12 b0 1e 6e 86 e0 8c 77 e0 55 8c c5 07 45 53 8d d5 8d 37 ce b5 72 54 69 98 4c e7 ac 49 ed 35 5b 17 e9 09 7d bc 56 47 c2 17 ce d2 5a 4f d0 9b c8 5f 25 91 09 b8 13 27 7e e4 82 cb 4d 4c 75 58 74 c2 82 df 7f 98 dd 84 57 f5 52 a7 ba bc 31 cf 67 25 64 28 9c 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_AMG_2147922441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.AMG!MTB"
        threat_id = "2147922441"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff d0 89 85 ?? ?? 00 00 8b 85 00 00 00 41 89 c0 ba 00 00 00 00 b9 ff ff ?? ?? 48 8b 05 ?? ?? ?? ?? ff d0 48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 c7 44 24 20 40 00 00 00 41 b9 00 10 00 00 41 b8 17 00 00 00 ba 00 00 00 00 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 4, accuracy: Low
        $x_1_2 = "WPCThdExRsFSngObjQIfpGD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_VG_2147924831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.VG!MTB"
        threat_id = "2147924831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Private Organization1" ascii //weight: 1
        $x_1_2 = "9113102459540314XR1" ascii //weight: 1
        $x_1_3 = "Langfang1503" ascii //weight: 1
        $x_1_4 = "Langfang Alkem Material Technology Co., Ltd.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_ZZ_2147925131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.ZZ!MTB"
        threat_id = "2147925131"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 85 c0 48 89 c3 0f 84 45 01 00 00 49 89 c4 48 89 c5 66 0f ef c0 48 01 be 80 20 00 00 49 c1 fc 15 0f 29 40 10 48 c1 fd 0c 48 89 78 08 48 c7 00 01 00 00 00 41 0f b6 c4 4c 8d 2c c6 49 8b 95 a8 20 00 00 48 85 d2 75 14 eb 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_ZZ_2147925131_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.ZZ!MTB"
        threat_id = "2147925131"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c8 49 c1 e9 04 49 f7 e2 4c 89 c8 48 89 d3 49 89 d2 49 f7 e3 48 89 f8 48 c1 eb 0b 48 c1 ea 02 48 6b d2 64 48 29 d0 48 81 f9 3f 42 0f 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 89 dc 4c 8b bc 24 b8 00 00 00 49 31 cc 4c 8b 8c 24 90 00 00 00 4c 89 e0 4c 89 de 4d 89 da 4c 31 da 4c 8b b4 24 98 00 00 00 4c 89 df 48 31 de 48 31 d0 4c 8b 84 24 90 00 00 00 49 31 ca 4d 31 ef 48 89 44 24 28 48 33 84 24 a8 00 00 00 4d 31 f9 4d 31 ce 4c 31 cb 4c 31 cf 48 89 5c 24 20 4c 89 d3 4d 31 f2 48 89 7c 24 30 48 89 cf 48 8b 4c 24 28 49 31 c5 4c 89 74 24 70 4c 8b b4 24 90 00 00 00 48 31 c7 48 89 f0 49 31 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_GB_2147925374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.GB!MTB"
        threat_id = "2147925374"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.PEB" ascii //weight: 1
        $x_1_2 = "main.IMAGE_DOS_HEADER" ascii //weight: 1
        $x_1_3 = "main.IMAGE_FILE_HEADER" ascii //weight: 1
        $x_1_4 = "main.IMAGE_OPTIONAL_HEADER32" ascii //weight: 1
        $x_1_5 = "main.IMAGE_OPTIONAL_HEADER64" ascii //weight: 1
        $x_1_6 = "main.PROCESS_BASIC_INFORMATION" ascii //weight: 1
        $x_1_7 = "shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_GPKL_2147927073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.GPKL!MTB"
        threat_id = "2147927073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 80 74 24 ?? 57 80 74 24 ?? 59 80 74 24 ?? 5b 80 74 24 ?? 5d 80 74 24 ?? 5f 80 74 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_GC_2147929369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.GC!MTB"
        threat_id = "2147929369"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.AesDecrypt" ascii //weight: 1
        $x_1_2 = "main.HexStrToBytes" ascii //weight: 1
        $x_1_3 = "main.isNonChinese" ascii //weight: 1
        $x_1_4 = "main.isNonChinese.deferwrap1" ascii //weight: 1
        $x_1_5 = "main.isPythonInCDrive" ascii //weight: 1
        $x_1_6 = "main.main" ascii //weight: 1
        $x_1_7 = "main.isCPULow" ascii //weight: 1
        $x_1_8 = "main.HideConsoleWindow" ascii //weight: 1
        $x_1_9 = "main.HexParseKey" ascii //weight: 1
        $x_1_10 = "/ShellCode/ShellCode" ascii //weight: 1
        $x_1_11 = "LazyDLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_RPH_2147931390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.RPH!MTB"
        threat_id = "2147931390"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\maldev\\!code-section\\!Shellcode\\Shellcode-test\\x64\\Release\\Shellcode-test.pdb" ascii //weight: 10
        $x_10_2 = "\\maldev\\!code-section\\!Shellcode\\Shellcode-obfuscated\\x64\\Release\\Shellcode-obfuscated.pdb" ascii //weight: 10
        $x_10_3 = "\\maldev\\code-section\\fud-cmd\\x64\\Release\\fud-cmd.pdb" ascii //weight: 10
        $x_10_4 = "\\maldev\\!code-section\\fud-cmd\\x64\\Release\\fud-cmd.pdb" ascii //weight: 10
        $x_1_5 = "curl_easy_perform cannot be executed if the CURL handle is used in a MultiPerform." ascii //weight: 1
        $x_1_6 = {68 74 74 70 73 3a 2f 2f [0-144] 2e 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ShellCodeRunner_MX_2147939134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.MX!MTB"
        threat_id = "2147939134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 01 00 4c 8b c7 48 8b d3 8b 08 e8 ?? 9a ff ff 8b d8 e8 61 05 00 00 84 c0 74 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_GZN_2147944522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.GZN!MTB"
        threat_id = "2147944522"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 44 24 30 4c c6 44 24 31 6f c6 44 24 32 61 c6 44 24 33 64 c6 44 24 34 4c c6 44 24 35 69 c6 44 24 36 62 c6 44 24 37 72 c6 44 24 38 61 c6 44 24 39 72 c6 44 24 3a 79 c6 44 24 3b 41 c6 44 24 3c 00 c6 44 24 40 47 c6 44 24 41 65 c6 44 24 42 74 c6 44 24 43 50 c6 44 24 44 72 c6 44 24 45 6f c6 44 24 46 63 c6 44 24 47 41 c6 44 24 48 64 c6 44 24 49 64 c6 44 24 4a 72 c6 44 24 4b 65 c6 44 24 4c 73 c6 44 24 4d 73 c6 44 24 4e 00 c6 44 24 28 57 c6 44 24 29 69 c6 44 24 2a 6e c6 44 24 2b 45 c6 44 24 2c 78 c6 44 24 2d 65 c6 44 24 2e 63}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_KKB_2147946090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.KKB!MTB"
        threat_id = "2147946090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 c2 48 8d 45 a0 b9 3a 08 00 00 4c 8b 00 4c 89 02 41 89 c8 49 01 d0 4d 8d 48 08 41 89 c8 49 01 c0 49 83 c0 08 4d 8b 40 f0 4d 89 41 f0 4c 8d 42 08 49 83 e0 f8 4c 29 c2 48 29 d0 01 d1 83 e1 f8 c1 e9 03 89 ca 89 d2 4c 89 c7 48 89 c6 48 89 d1 f3 48 a5}  //weight: 10, accuracy: High
        $x_10_2 = {8b 85 fc 07 00 00 48 98 0f b6 44 05 a0 8b 95 fc 07 00 00 48 63 ca 48 8b 95 f0 07 00 00 48 01 ca 32 85 fb 07 00 00 88 02 83 85 fc 07 00 00 01 8b 85 fc 07 00 00 3d 39 08 00 00 76}  //weight: 10, accuracy: High
        $x_3_3 = {41 b9 40 00 00 00 41 b8 00 30 00 00 ba 3a 08 00 00 b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0 48 89 85}  //weight: 3, accuracy: Low
        $x_2_4 = {48 89 84 24 87 00 00 00 48 b8 41 64 64 72 65 73 73 00 48 89 84 24 8e 00 00 00 c7 84 24 81 00 00 00 ?? ?? ?? ?? 66 c7 84 24 85 00 00 00 70 00 48 b8 45 78 69 74 50 72 6f 63 48 89 44 24 75 c7 44 24 7d ?? ?? ?? ?? 48 b8 57 73 32 5f 33 32 2e 64 48 89 44 24 6a c7 44 24 71 ?? ?? ?? ?? 48 b8 57 53 41}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ShellCodeRunner_KAB_2147947323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.KAB!MTB"
        threat_id = "2147947323"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 89 c2 48 8d 45 a0 b9 20 08 00 00 4c 8b 00 4c 89 02 41 89 c8 49 01 d0 4d 8d 48 08 41 89 c8 49 01 c0 49 83 c0 08 4d 8b 40 f0 4d 89 41 f0 4c 8d 42 08 49 83 e0 f8 4c 29 c2 48 29 d0 01 d1 83 e1 f8 c1 e9 03 89 ca 89 d2 4c 89 c7 48 89 c6 48 89 d1 f3 48 a5}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_KAC_2147948346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.KAC!MTB"
        threat_id = "2147948346"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 8d 55 a0 48 8b 85 ?? ?? 00 00 48 01 d0 0f b6 00 48 8b 8d ?? ?? 00 00 48 8b 95 ?? ?? 00 00 48 01 ca 32 85 ?? ?? 00 00 88 02}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_AR_2147951146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.AR!MTB"
        threat_id = "2147951146"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 8d 8c 03 00 00 48 63 c1 48 69 c0 56 55 55 55 48 c1 e8 20 48 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 01 d0 29 c1 89 ca 8b 85 58 03 00 00}  //weight: 10, accuracy: High
        $x_8_2 = {89 c2 89 d0 48 69 c0 d3 4d 62 10 48 c1 e8 20 c1 e8 05 69 c0 f4 01 00 00 29 c2 89 d0 05 f4 01 00 00 89 c1}  //weight: 8, accuracy: High
        $x_5_3 = {48 8b 55 d0 48 8b 45 a8 48 01 d0 0f b6 00 0f b6 c0 48 8b 4d d0 48 8b 55 a8 48 8d 1c 11 89 c1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_GPAA_2147952857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.GPAA!MTB"
        threat_id = "2147952857"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {62 27 68 87 03 49 3b 87 03 49 3b 87 03 49 3b 54 71 4a 3a 82 03 49 3b 54 71 4c 3a 11 03 49 3b 54 71 4d 3a 8d 03 49 3b 26 74 4d 3a 89 03 49 3b 26 74 4a 3a 8e 03 49 3b 26 74 4c 3a b7 03 49 3b 54 71 48 3a 84 03 49 3b 87}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_GVN_2147955212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.GVN!MTB"
        threat_id = "2147955212"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {42 0f b6 4c 14 24 44 31 d9 88 4c 24 26 48 8d 5c 24 26}  //weight: 2, accuracy: High
        $x_1_2 = {46 0f b6 64 24 24 48 89 c1 4c 89 f8 48 99 49 f7 fa 45 31 dc 66 90 4c 39 d2 0f 83 3b 01 00 00 48 8b 35 10 e1 2a 00 0f b6 14 32 41 31 d4 44 88 64 24 26 48 89 c8 48 8d 5c 24 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_KAE_2147955793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.KAE!MTB"
        threat_id = "2147955793"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b 45 18 8b 00 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 48 0f be c0 48 01 45 f8 48 8b 45 18 8b 00 8d 50 01 48 8b 45 18 89 10}  //weight: 20, accuracy: High
        $x_10_2 = {48 8b 45 18 8b 00 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 84 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_GDZ_2147958818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.GDZ!MTB"
        threat_id = "2147958818"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8d 7b f8 49 89 be ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b c8 48 8d 54 24 40 ff 15 ?? ?? ?? ?? 83 7c 24 40 00 74 ?? b9 ff ff ff ff ff 15 ?? ?? ?? ?? cc 48 8d 46 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_GVC_2147959024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.GVC!MTB"
        threat_id = "2147959024"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 55 f8 48 8b 45 ?? 48 01 d0 0f b6 00 48 8b 4d f8 48 8b 55 ?? 48 01 ca 32 45 c7 88 02 [0-15] 48 83 45 ?? 01 48 8b 45 ?? 48 3b 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

