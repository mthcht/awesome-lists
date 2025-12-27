rule Trojan_Win64_Cobaltstrike_RN_2147771633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RN!dha"
        threat_id = "2147771633"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 29 d0 40 32 34 04 89 f0 41 31 c0 45 88 04 ?? 48 83 c1 01 45 89 ?? 41 39}  //weight: 1, accuracy: Low
        $x_1_2 = {4a 46 49 46 c6 44 24 ?? ?? e8 ?? ?? ?? ?? 85 c0 [0-10] c6 05 ?? ?? ?? ?? 6a c6 05 ?? ?? ?? ?? 70}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 85 c0 75 ?? 8b 44 24 ?? 48 8b 4c 24 ?? 45 31 c0 48 01 c8 8d 14 01 48 63 d2 48 89 15 ?? ?? ?? ?? ba 01 00 00 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 e9 10 a9 80 80 00 00 0f 44 c1 48 8d 4a 02 89 ?? 48 0f 44 d1 40 00 ?? 48 8b 05 ?? 48 83 da 03 c7 02 41 6c 6c 6f 66}  //weight: 1, accuracy: Low
        $x_1_5 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 [0-32] 2e 6a 70 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RN_2147771633_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RN!dha"
        threat_id = "2147771633"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c8 45 0f b6 4c 0a 30 48 [0-48] 89 ?? 41 31 c0 45 88 04 0a 48 83 c1 01 45 89 c8 41 39 cb 7f ?? 31 c0 48 81 c4 ?? 00 00 00 5b 5e 5f c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 b8 53 4f 46 54 57 41 52 45 c7 44 24 60 66 74 5c 43 c6 44 24 66 00 48 89 44 24 50 48 b8 5c 4d 69 63 72 6f 73 6f 4c 8d 44 24 48 48 89 44 24 58 b8 54 46 00 00 ?? 89 ea 66 89 44 24 64 48 c7 c1 01 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 31 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {09 05 00 d8 0f 85 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 41 b8 04 00 00 00 48 89 ?? c7 44 24 70 4a 46 49 46 c6 44 24 74 00 e8 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? c6 05 ?? ?? 05 00 6a c6 05 ?? ?? 05 00 70 c6 05 ?? ?? 05 00 65 c6 05 ?? ?? 05 00 67 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DL_2147785258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DL!MTB"
        threat_id = "2147785258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c9 4d 8d 40 01 49 83 fa 15 49 0f 45 ca 41 ff c1 42 0f b6 04 19 4c 8d 51 01 41 30 40 ff 41 81 f9 cc 01 00 00 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DL_2147785258_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DL!MTB"
        threat_id = "2147785258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 c7 44 24 04 00 00 00 00 b8 90 5f 01 00 48 03 05 da 2f 00 00 41 5a 48 ff e0}  //weight: 10, accuracy: High
        $x_5_2 = "3e3m1l0e0e0g0h0i0f0k0l0m0n0o0p0q0r1c1d1" ascii //weight: 5
        $x_3_3 = "Retpoline" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DL_2147785258_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DL!MTB"
        threat_id = "2147785258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 29 c0 8b 05 ?? ?? ?? ?? 41 29 c0 8b 05 ?? ?? ?? ?? 41 29 c0 8b 05 ?? ?? ?? ?? 41 29 c0 44 89 c0 4c 63 c0 48 8b 45 ?? 4c 01 c0 0f b6 00 31 c8 88 02 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "n%r!w?$+OVwdvh57$7A@31T+KO6jJs!i2rf#S<vk^ZDjZ5V2iM3%o4Q2<6+D(G" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_HGF_2147795822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.HGF!MTB"
        threat_id = "2147795822"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 89 c9 45 31 c1 89 c2 44 31 c2 bd ?? ?? ?? ?? 45 89 ca 41 21 ea 81 e1 ?? ?? ?? ?? 44 09 d1 21 d5 25 ?? ?? ?? ?? 09 e8 31 c8 44 09 ca 44 31 c2 09 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DG_2147798750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DG!MTB"
        threat_id = "2147798750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fb 48 c1 f9 ?? 0f b6 c9 0f bf 14 48 c1 ea ?? 83 e2 ?? c1 ff ?? 85 d2 74}  //weight: 1, accuracy: Low
        $x_1_2 = {80 30 ee ff c1 48 8d 40 ?? 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DG_2147798750_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DG!MTB"
        threat_id = "2147798750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 cb 44 29 c3 41 89 d8 46 8d 0c 02 44 8b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 41 0f af d0 45 8d 04 11 8b 15 ?? ?? ?? ?? 41 01 d0 8b 15 ?? ?? ?? ?? 41 01 d0 8b 15 ?? ?? ?? ?? 44 01 c2 48 63 d2 48 03 55 10 0f b6 12 31 ca 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = "QAnxk<wngwzajvk0h)1aYyRPd6PV?u9+_8igdWP&GEl%6CvqB<rpsOcZZ6@CtS<l&DzHFxUF)oSXI4U$rViQV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DG_2147798750_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DG!MTB"
        threat_id = "2147798750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 54 03 ?? 48 89 f1 4c 8d 40 01 48 c1 f9 08 31 f2 31 ca 48 89 f1 48 c1 f9 10 31 ca 48 89 f1 48 c1 f9 18 31 ca 48 8d 4e 01 88 54 03 ?? 49 39 f8 0f 8d}  //weight: 10, accuracy: Low
        $x_10_2 = {48 39 ce 7e ?? 30 54 0b ?? 48 8d 48 0a 48 39 ce 7e ?? 30 54 0b ?? 48 8d 48 0b 48 39 ce 7e ?? 30 54 0b ?? 48 8d 48 0c 48 39 ce 7e ?? 30 54 0b ?? 48 8d 48 0d 48 39 ce 7e ?? 30 54 0b ?? 48 83 c0 0e 48 39 c6 7e}  //weight: 10, accuracy: Low
        $x_10_3 = {30 54 0b 10 48 8d 48 ?? 48 39 ce 7e ?? 30 54 0b 10 48 8d 48 ?? 48 39 ce 7e ?? 30 54 0b 10 48 8d 48 ?? 48 39 ce 7e ?? 30 54 0b 10 48 8d 48 ?? 48 39 ce 7e ?? 48 83 c0 06 30 54 0b 10 48 39 c6 7e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DH_2147807883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DH!MTB"
        threat_id = "2147807883"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 c1 41 83 e1 ?? 47 8a 0c 08 44 32 0c 01 48 ff c0 44 88 48 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DH_2147807883_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DH!MTB"
        threat_id = "2147807883"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hq8cwXh7^3d*eFcRU4TGcQ2>1x>&TW?t)7pS4R*" ascii //weight: 1
        $x_1_2 = "xfadqKKcbGfTaE" ascii //weight: 1
        $x_1_3 = "GetCommandLineA" ascii //weight: 1
        $x_1_4 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_5 = "NoRecentDocsHistory" ascii //weight: 1
        $x_1_6 = "NoDrives" ascii //weight: 1
        $x_1_7 = "NoRun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DJ_2147807885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DJ!MTB"
        threat_id = "2147807885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "ertfgyhfrhsdsj" ascii //weight: 1
        $x_1_3 = "hghjfuigsygdhxskeryfh" ascii //weight: 1
        $x_1_4 = "jhhfghfhgff" ascii //weight: 1
        $x_1_5 = "kfgsrsrtfkdhsreyk" ascii //weight: 1
        $x_1_6 = "xfGadsgeufhrk" ascii //weight: 1
        $x_1_7 = "NoRemove" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_9 = "ClientToScreen" ascii //weight: 1
        $x_1_10 = "MsTeg.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DI_2147808443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DI!MTB"
        threat_id = "2147808443"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 3d ?? ?? ?? ?? 77 ?? 8b 85 ?? ?? ?? ?? 48 98 0f b6 44 05 ?? 32 85 ?? ?? ?? ?? 89 c2 8b 85 ?? ?? ?? ?? 48 98 88 54 05 ?? 83 85 ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DI_2147808443_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DI!MTB"
        threat_id = "2147808443"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 84 24 88 00 00 00 99 b9 04 00 00 00 f7 f9 83 fa 01 41 0f 94 c0 41 80 e0 01 44 88 84 24 94 00 00 00 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 41 89 c9 41 83 e9 01 41 0f af c9 83 e1 01 83 f9 00 41 0f 94 c0 83 fa 0a 41 0f 9c c2 45 08 d0 41 f6 c0 01 b9 26 c4 9f ff ba da ac a6 46 0f 45 d1 89 94 24 80 00 00 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DM_2147809865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DM!MTB"
        threat_id = "2147809865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 07 4c 8d 44 24 30 34 45 48 63 ee 49 03 ee 88 44 24 30 48 8b d5 4c 89 6c 24 20 41 b9 01 00 00 00 49 8b cf 41 ff d4 85 c0 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DN_2147810692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DN!MTB"
        threat_id = "2147810692"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c2 48 8d 4d c0 48 03 c8 0f b6 01 41 88 04 38 44 88 09 41 0f b6 04 38 41 03 c1 0f b6 c0 0f b6 4c 05 c0 41 30 0a 49 ff c2 49 83 ee 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_ROX_2147810781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.ROX!MTB"
        threat_id = "2147810781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 0a 41 88 0c 28 44 88 0a 41 0f b6 14 28 49 03 d1 0f b6 ca 0f b6 94 0c 50 04 00 00 41 30 12 49 ff c2 49 83 eb 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DO_2147812416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DO!MTB"
        threat_id = "2147812416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c3 41 2a c5 24 08 32 03 40 32 c7 88 03 49 03 df 48 3b dd 72}  //weight: 1, accuracy: High
        $x_1_2 = "ingamerush.dll" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "CreateFileW" ascii //weight: 1
        $x_1_6 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DP_2147812780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DP!MTB"
        threat_id = "2147812780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 ca f6 d2 89 cb f6 d3 41 89 d2 41 80 e2 ?? 41 80 e1 ?? 45 08 d1 08 da 80 e3 ?? 80 e1 ?? 08 d9 44 30 c9 f6 d2 08 ca 88 54 24 ?? 0f b6 4c 24 ?? 0f b6 5c 24 ?? 89 da f6 d2 20 ca f6 d1 20 d9 08 d1 88 4c 24 ?? 80 44 24 2a 01 0f b6 4c 24 ?? 48 8b 54 24 ?? 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DQ_2147813837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DQ!MTB"
        threat_id = "2147813837"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 c1 48 8d 43 01 49 2b d3 4d 03 c6 4a 8d 0c a5 ?? ?? ?? ?? 49 0f af c3 48 2b c7 49 0f af d2 48 ff c8 49 0f af cc 48 0f af c3 48 03 d0 48 8d 04 7f 48 03 d0 48 2b d6 48 03 d5 49 8d 04 ?? 0f b6 0c 01 48 8b 44 24 68 41 30 0c 01}  //weight: 1, accuracy: Low
        $x_1_2 = "J>@Y@N%pf>(lMO8K!COzQoYL2^L)T>D1g*$kl$bNM2m1hk!+mtLu^*xJmiI3mP(jZjE&(QndR#7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DR_2147813838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DR!MTB"
        threat_id = "2147813838"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllMain" ascii //weight: 10
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "yzdgtuymu.dll" ascii //weight: 1
        $x_1_4 = "bfqlvkkjyetvkx" ascii //weight: 1
        $x_1_5 = "cjnvbiszpyzevj" ascii //weight: 1
        $x_1_6 = "ebxetsdkanuzfqltk" ascii //weight: 1
        $x_1_7 = "gosdwzjmndmeoguiw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DS_2147814118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DS!MTB"
        threat_id = "2147814118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 13 49 8b c8 f6 d2 4c 3b c7 73 17 0f 1f 00 0f b6 c1 40 2a c6 32 01 32 c2 88 01 49 03 cb 48 3b cf 72 ec 49 ff c0 48 ff c3 49 83 ea 01 75 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DS_2147814118_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DS!MTB"
        threat_id = "2147814118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 0f b6 0c 00 44 33 c9 44 8b 05 ?? ?? ?? ?? 44 0f af 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 44 24 ?? 2b c1 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 8b c2 03 c1 8b 0d ?? ?? ?? ?? 03 c8 41 8b c0 03 c1 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b c8 48 8b 44 24 ?? 44 88 0c 08}  //weight: 1, accuracy: Low
        $x_1_2 = "U>@?xm6P$6qoL_QSDHdoVnoOcALCXXz&L6nEgq#v3%5W$0JR+F@yF?cI^r2p&z*bQ*n%fCDn%Ea548)%?D" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DT_2147814120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DT!MTB"
        threat_id = "2147814120"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 28 39 04 24 7d 35 48 8b 44 24 08 0f b6 00 33 44 24 38 48 8b 4c 24 08 88 01 48 8b 44 24 08 0f b6 00 2b 44 24 30 48 8b 4c 24 08 88 01 48 8b 44 24 08 48 ff c0 48 89 44 24 08 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DT_2147814120_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DT!MTB"
        threat_id = "2147814120"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllMain" ascii //weight: 10
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "pbmbduau.dll" ascii //weight: 1
        $x_1_4 = "doeqzhswetaqzurtk" ascii //weight: 1
        $x_1_5 = "ffgqcxzhepurelaij" ascii //weight: 1
        $x_1_6 = "jnsxdakhdofxxq" ascii //weight: 1
        $x_1_7 = "kpqhbjhosaearus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DU_2147814121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DU!MTB"
        threat_id = "2147814121"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 fe c2 48 8d 5b 01 45 0f b6 d2 4f 8d 04 93 45 8b 48 08 41 02 c1 0f b6 c0 41 8b 54 83 08 41 89 50 08 41 02 d1 45 89 4c 83 08 0f b6 ca 41 0f b6 54 8b 08 30 53 ff 48 ff cf 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DU_2147814121_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DU!MTB"
        threat_id = "2147814121"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 58 49 2b d7 46 0f b6 04 1a 49 03 c2 42 0f b6 0c 18 b8 ?? ?? ?? ?? 44 03 c1 48 8b 8c 24 ?? ?? ?? ?? 41 f7 e8 c1 fa 0a 8b c2 c1 e8 1f 03 d0 69 d2 ?? ?? ?? ?? 44 2b c2 49 63 c0 48 2b c6 48 03 c5 42 0f b6 04 18 30 04 0b}  //weight: 1, accuracy: Low
        $x_1_2 = "abb3l_s4Wy>%Rs!k^Z!?(r_U2Be)V7#RY&U8kTb4%(cK6r&3297WYZIJujPyK4z%VvCE^Xr)Iy4aSw$rGXWOrHeqmw&s(2!LbU*e9KmCdMwuZH&w" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DV_2147814122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DV!MTB"
        threat_id = "2147814122"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 03 d1 48 8b ca 48 33 c8 48 8b c1 48 0f be 4c 24 30 48 33 c8 48 8b c1 48 8b 8c 24 f0 00 00 00 88 84 0c ac 00 00 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DV_2147814122_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DV!MTB"
        threat_id = "2147814122"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 60 49 03 c2 42 0f b6 0c 18 b8 ?? ?? ?? ?? 44 03 c1 48 8b 8c 24 ?? ?? ?? ?? 41 f7 e8 41 03 d0 c1 fa 0d 8b c2 c1 e8 1f 03 d0 69 d2 ?? ?? ?? ?? 44 2b c2 49 63 c0 48 03 44 24 70 49 03 c5 48 03 c6 42 0f b6 04 18 30 04 0b}  //weight: 1, accuracy: Low
        $x_1_2 = ">eA)#OoOjAPVesPa2LD(uz4D6<t&tfHHIUnuGgunWDIQERkCEN@rFYPecZ_AbeCzEEWhh4HZpEGHHtWw>x3$u#DxZFuibmDLRbg1fv*4@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AD_2147814220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AD!MTB"
        threat_id = "2147814220"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 17 00 00 00 c1 e2 05 8b c2 41 83 e8 2c 4c 0f af c0 49 8b c2 49 f7 e0 48 c1 ea 07 48 69 c2 ff 00 00 00 41 8b d4 4c 2b c0 41 0f b6 c0 0f 45 c8 41 88 0c 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AD_2147814220_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AD!MTB"
        threat_id = "2147814220"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 31 04 09 49 83 c1 ?? 8b 83 ?? ?? ?? ?? 01 43 ?? 8b 93 ?? ?? ?? ?? 8b 43 ?? 81 c2 ?? ?? ?? ?? 03 53 ?? 2b 43 ?? 33 d0 81 f2 ?? ?? ?? ?? 89 53 ?? 49 81 f9 ?? ?? ?? ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DW_2147814539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DW!MTB"
        threat_id = "2147814539"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 f8 08 48 c1 f9 08 0f b6 d1 32 84 3a 80 01 04 00 88 46 fe 43 8d 04 3a 99 41 ff c7 f7 fd 48 63 c2 0f b6 8c 83 58 04 00 00 44 32 84 39 80 01 04 00 44 88 46 ff 4d 3b cd 0f}  //weight: 2, accuracy: High
        $x_2_2 = {44 89 64 24 30 4c 8d 4c 24 30 ba 08 00 00 00 44 8d 42 38 49 8b ce ff 15 ?? ?? 02 00 33 c9 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DW_2147814539_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DW!MTB"
        threat_id = "2147814539"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 48 63 c8 48 8b 44 24 70 0f b6 0c 08 48 8b 44 24 78 0f b6 04 10 33 c1 89 44 24 14 8b 05 ?? ?? ?? ?? 0f af 05}  //weight: 1, accuracy: Low
        $x_1_2 = "oWhOz?WXuR3gjLxeljCw3Tc>dI(d_vptKd8mNOfWX+sHRPxQsUpl1HyM3<gcS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DX_2147814629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DX!MTB"
        threat_id = "2147814629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 2b 05 ?? ?? ?? ?? 48 63 c8 48 8b 44 24 50 0f b6 0c 08 48 8b 44 24 58 44 0f b6 24 10 44 33 e1 8b 2d ?? ?? ?? ?? 0f af 2d ?? ?? ?? ?? 8b 35}  //weight: 1, accuracy: Low
        $x_1_2 = "fu+meN!_DzXF!FDBMUg8Z*3zbI4<i+yZ<Dny9awo)#Sd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EA_2147814886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EA!MTB"
        threat_id = "2147814886"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dll3.dll" ascii //weight: 1
        $x_1_2 = "Cseeg" ascii //weight: 1
        $x_1_3 = "QueueUserAPC" ascii //weight: 1
        $x_1_4 = "ShellExecuteW" ascii //weight: 1
        $x_1_5 = "microsoftdnsserver.xyz:2087" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EA_2147814886_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EA!MTB"
        threat_id = "2147814886"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllMain" ascii //weight: 10
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "nsefdwuahp.dll" ascii //weight: 1
        $x_1_4 = "ambxsvboxrxrat" ascii //weight: 1
        $x_1_5 = "bvayetyzrmlbwlo" ascii //weight: 1
        $x_1_6 = "cscudbkisfunsy" ascii //weight: 1
        $x_1_7 = "eiygygmyodoawftt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EB_2147814887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EB!MTB"
        threat_id = "2147814887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 89 c3 31 c0 39 c6 7e 15 48 89 c2 83 e2 07 8a 54 15 00 32 14 07 88 14 03 48 ff c0 eb e7}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EB_2147814887_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EB!MTB"
        threat_id = "2147814887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {2b c1 44 8b c0 48 8b 93 f8 00 00 00 48 8b 8b a8 00 00 00 48 2b cf 48 8b 42 50 48 0f af c1 48 89 42 50 49 83 e8 01 75 dd 48 8b 83 d8 00 00 00 8b 88 38 01}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EB_2147814887_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EB!MTB"
        threat_id = "2147814887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {49 83 c0 01 f7 ed c1 fa 03 8b c2 c1 e8 1f 03 d0 48 63 c5 83 c5 01 48 63 ca 48 6b c9 21 48 03 c8 48 8b 44 24 38 42 0f b6 8c 31 b0 98 04 00 41 32 4c 00 ff 41 88 4c 18 ff}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EB_2147814887_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EB!MTB"
        threat_id = "2147814887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UnhookingPatch\\PatchingAPI\\x64\\Release\\PatchingAPI.pdb" ascii //weight: 1
        $x_1_2 = "NtWaitForSingleONtAllocateVirtuaNtProtectVirtualNtCreateThreadEx" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "CryptCreateHash" ascii //weight: 1
        $x_1_6 = "CryptDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EB_2147814887_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EB!MTB"
        threat_id = "2147814887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "ucjkzslijbmtds.dll" ascii //weight: 1
        $x_1_3 = "cvxdemwflfsdxylza" ascii //weight: 1
        $x_1_4 = "luqwnpprdtpkbf" ascii //weight: 1
        $x_1_5 = "pscsqsumvfoefoub" ascii //weight: 1
        $x_1_6 = "rqxqkwcihftzaiypk" ascii //weight: 1
        $x_1_7 = "ggdfhxuszqfcio.dll" ascii //weight: 1
        $x_1_8 = "crczxvkgosonk" ascii //weight: 1
        $x_1_9 = "ojzlzjbdurbnhiyw" ascii //weight: 1
        $x_1_10 = "rpixqbomgkhcbjn" ascii //weight: 1
        $x_1_11 = "ublanfkoazneyu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Cobaltstrike_ED_2147814997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.ED!MTB"
        threat_id = "2147814997"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "sajmghnmbzau.dll" ascii //weight: 1
        $x_1_3 = "aqxvpbhhekqluzmmt" ascii //weight: 1
        $x_1_4 = "bkybynrvotbwljn" ascii //weight: 1
        $x_1_5 = "cwacrxmzkkqnmu" ascii //weight: 1
        $x_1_6 = "fdrypcdprnrjroqxq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_CMN_2147818083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.CMN!MTB"
        threat_id = "2147818083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 ff c0 89 44 24 20 48 8b 44 24 28 0f b7 40 06 39 44 24 20 7d 4a 48 8b 44 24 40 8b 40 10 48 8b 4c 24 40 8b 49 14 48 03 4c 24 30 48 8b 54 24 40 8b 52 0c 48 03 54 24 38 48 89 54 24 58 44 8b c0 48 8b d1 48 8b 44 24 58 48 8b c8 e8 ?? ?? ?? ?? 48 8b 44 24 40 48 83 c0 28 48 89 44 24 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_HFG_2147818084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.HFG!MTB"
        threat_id = "2147818084"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c1 2a c3 24 c0 41 32 c0 30 01 48 03 ce 49 3b ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_IHJ_2147818085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.IHJ!MTB"
        threat_id = "2147818085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 2b c1 48 8b 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_CTI_2147826133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.CTI!MTB"
        threat_id = "2147826133"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 00 0f b6 c0 48 98 8b 44 85 a0 0f b6 c0 c1 e0 06 89 c1 8b 85 a8 01 00 00 48 98 48 8d 50 03 48 8b 85 d0 01 00 00 48 01 d0 0f b6 00 0f b6 c0 48 98 8b 44 85 a0 09 c1 8b 85 a4 01 00 00 48 98 48 8d 50 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AG_2147828577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AG!MTB"
        threat_id = "2147828577"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bypass\\CallDLLDynamic\\x64\\Release\\testDLL.pdb" ascii //weight: 1
        $x_1_2 = "testDLL.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AG_2147828577_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AG!MTB"
        threat_id = "2147828577"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c7 ff c5 41 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 d0 0f b6 c2 c0 e0 02 8d 0c 10 02 c9 44 2a c9 41 80 c9 30 44 88 4c 3c 1f 44 8b ca 85 d2 75 cb}  //weight: 1, accuracy: High
        $x_1_2 = "JGANV*T(XB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AG_2147828577_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AG!MTB"
        threat_id = "2147828577"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 84 04 ?? ?? ?? ?? 48 8b 4c 24 ?? 0f b6 09 33 c8 8b c1 48 8b 4c 24 ?? 88 01 8b 44 24 20 ff c0 89 44 24 20 8b 44 24 20 83 e0 07 89 44 24 20 eb}  //weight: 4, accuracy: Low
        $x_1_2 = "RdvServiceMain@@YAXPEAX0K0K@Z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_ACS_2147828578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.ACS!MTB"
        threat_id = "2147828578"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 63 c8 48 8d 54 24 40 48 03 d1 0f b6 0a 41 88 09 44 88 12 41 0f b6 11 49 03 d2 0f b6 ca 0f b6 54 0c 40 41 30 13 49 ff c3 48 83 eb 01 75 97}  //weight: 5, accuracy: High
        $x_5_2 = {49 63 c0 48 8d 4d 80 48 03 c8 0f b6 01 41 88 04 31 44 88 11 41 0f b6 0c 31 49 03 ca 0f b6 c1 0f b6 4c 05 80 30 4c 1c 2b 48 83 c3 0c 48 83 fb 54 0f 8c}  //weight: 5, accuracy: High
        $x_1_3 = "cd0951933892e688f" ascii //weight: 1
        $x_1_4 = "3ed16cdb912d7f435" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Cobaltstrike_FE_2147828595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.FE!MTB"
        threat_id = "2147828595"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 4c 14 08 44 89 04 24 89 54 24 04 44 88 54 14 08 41 8d 04 0a 43 88 0c 01 0f b6 c8 0f b6 44 0c 08 42 32 44 1f ff 41 88 43}  //weight: 1, accuracy: High
        $n_1_2 = "D:\\svn2\\kddriver\\kd_driver_config\\x64\\Release\\KDDriverSetting.pdb" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_BMA_2147828679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.BMA!MTB"
        threat_id = "2147828679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Users\\hyx19\\Downloads\\apps" ascii //weight: 1
        $x_1_2 = "microsoftservice.oss-cn-hangzhou@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_FF_2147828699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.FF!MTB"
        threat_id = "2147828699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 00 48 63 4c 24 34 0f b6 8c 0c 80 00 00 00 33 c1 88 44 24 2c 0f b6 54 24 2c 48 8d 4c 24 60}  //weight: 1, accuracy: High
        $x_1_2 = {40 32 2c 11 41 8d 53 ff 40 88 2c 11 44 32 34 01 44 89 d8 44 88 34 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Cobaltstrike_FG_2147828700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.FG!MTB"
        threat_id = "2147828700"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 28 00 00 00 00 8b 44 24 24 48 63 4c 24 28 0f b6 4c 0c 50 48 8b 94 24 ?? ?? ?? ?? 0f b6 04 02 33 c1 8b 4c 24 24 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 8b 44 24 28 ff c0 89 44 24 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_FG_2147828700_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.FG!MTB"
        threat_id = "2147828700"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 0c ?? 42 32 44 0f ?? 41 88 41 ?? 41 8d 42 ?? 41 83 c2 04 48 63 c8 49 8b c0 48 f7 e1 48 c1 ea 02 48 6b c2 16 48 2b c8 0f b6 44 0c ?? 42 32 44 0e ?? 41 88 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RDE_2147829001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RDE!MTB"
        threat_id = "2147829001"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 4d 8d 40 01 49 83 f9 60 49 0f 45 c9 0f b6 44 0c 40 43 32 44 18 ff 42 88 84 04 af 00 00 00 33 c0 49 83 f9 60 4c 8d 49 01 0f 45 c2 41 ff c2 8d 50 01 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RE_2147829600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RE!MTB"
        threat_id = "2147829600"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 f8 0d 49 63 c8 48 8b d3 4d 8d 49 01 48 0f 45 d0 48 03 4d d0 41 ff c0 0f b6 44 14 60 41 32 41 ff 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EL_2147830039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EL!MTB"
        threat_id = "2147830039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 2b 05 ?? ?? ?? ?? 48 63 c8 48 8b 44 24 50 0f b6 0c 08 48 8b 44 24 58 0f b6 2c 10 33 e9 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 0f af 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EM_2147830402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EM!MTB"
        threat_id = "2147830402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5b 53 5f b0 c6 fc ae 75 fd 57 59 53 5e 8a 06 30 07}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EM_2147830402_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EM!MTB"
        threat_id = "2147830402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 1e ff 41 03 d0 c1 fa 09 8b ca c1 e9 1f 03 d1 69 ca 7b 03 00 00 44 2b c1 41 fe c0 41 32 c0 40 32 c5 88 43 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EM_2147830402_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EM!MTB"
        threat_id = "2147830402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 cb 31 d2 4c 89 e1 ff 15 ?? ?? ?? ?? 49 89 c0 31 c0 48 89 c2 83 e2 07 8a 14 17 32 14 06 41 88 14 00 48 ff c0 39 c3 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EM_2147830402_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EM!MTB"
        threat_id = "2147830402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Petkeeemysec" ascii //weight: 1
        $x_1_2 = "tkceemysecretkeeemysecretkeeemysecretk" ascii //weight: 1
        $x_1_3 = "ysecretkeeemype" ascii //weight: 1
        $x_1_4 = "tetkeeemysecretkeeemysecretE" ascii //weight: 1
        $x_1_5 = "\\kaplya.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RDB_2147833449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RDB!MTB"
        threat_id = "2147833449"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b0 01 c6 45 20 00 48 8d 55 20 49 8b ce e8 b3 04 00 00 41 b0 01 c6 45 20 00 48 8d 55 20 49 8b ce e8 50 06 00 00 41 b0 01 c6 45 20 00 48 8d 55 20 49 8b ce e8 ed 07 00 00 41 b0 01 c6 45 20 00 48 8d 55 20 49 8b ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RDC_2147833714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RDC!MTB"
        threat_id = "2147833714"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 04 01 48 8b 4c 24 40 48 8b 54 24 28 0f be 0c 11 33 c8 8b c1 8b 4c 24 20 48 8b 54 24 40 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_2147835800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.MT!MTB"
        threat_id = "2147835800"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 28 48 89 38 48 8b 44 24 40 48 89 44 24 30 b9 01 00 00 00 ff d3 48 89 44 24 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_2147835800_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.MT!MTB"
        threat_id = "2147835800"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f af c2 29 c1 89 c8 48 63 d0 48 8d 05 ?? ?? ?? ?? 0f b6 04 02 44 31 c8 41 88 00 83 45 fc 01 8b 45 fc 48 63 d0 48 8b 45 e8 48 39 c2 0f 82}  //weight: 5, accuracy: Low
        $x_2_2 = "AAAWiejZmqLvmRaSWsqDoOrq" ascii //weight: 2
        $x_2_3 = "AAZkPGizvIgtSVM" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AF_2147841318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AF!MTB"
        threat_id = "2147841318"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 89 c8 99 44 8b 4d ?? 41 f7 f9 4c 63 d2 42 0f b6 14 11 41 31 d0 45 88 c3 48 8b 8d ?? ?? ?? ?? 4c 63 55 ?? 46 88 1c 11 8b 45 ?? 83 c0 ?? 89 45 28 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RPY_2147841716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RPY!MTB"
        threat_id = "2147841716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 41 b8 00 02 04 00 48 8b cb ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RPY_2147841716_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RPY!MTB"
        threat_id = "2147841716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 0d 3b 10 00 00 ba 05 00 00 00 80 34 3e 05 ff 15 24 10 00 00 48 ff c6 48 81 fe 7b 03 00 00 72 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RPY_2147841716_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RPY!MTB"
        threat_id = "2147841716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c7 84 24 20 03 00 00 00 00 00 00 c7 84 24 28 03 00 00 00 00 00 00 48 8d 84 24 28 03 00 00 48 89 44 24 28 c7 44 24 20 00 00 00 00 31 c9 31 d2 49 89 d8 45 31 c9 e8 d2 ad 03 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b b4 24 a0 00 00 00 4c 8b bc 24 a8 00 00 00 48 8b bc 24 b0 00 00 00 31 c9 48 89 fa 41 b8 00 30 00 00 41 b9 40 00 00 00 e8 cf ac 03 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RPZ_2147841718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RPZ!MTB"
        threat_id = "2147841718"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 f7 e8 41 03 d0 c1 fa 09 8b ca c1 e9 1f 03 d1 69 ca ac 03 00 00 44 2b c1 41 fe c0 44 32 44 2b ff 45 32 c7 44 88 43 ff 48 83 ef 01 75 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RPZ_2147841718_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RPZ!MTB"
        threat_id = "2147841718"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b c8 c7 44 24 28 40 00 00 00 c7 44 24 20 00 30 00 00 4c 8d 4d c8 45 33 c0 48 8d 55 b0 ff d3 ff d7 48 8b 5d b0 4c 8d 4d b8 ba 0f 27 00 00 41 b8 40 00 00 00 48 8b cb ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RPX_2147843430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RPX!MTB"
        threat_id = "2147843430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c2 83 e2 03 8a 54 15 00 32 14 07 88 14 03 48 ff c0 eb e7}  //weight: 1, accuracy: High
        $x_1_2 = {49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RPX_2147843430_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RPX!MTB"
        threat_id = "2147843430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d e8 b8 e3 01 00 00 8b 55 f4 44 8b 4d f0 2b d0 44 8b 55 e0 41 81 f1 f0 00 00 00 44 8b 45 e4 41 81 ea ab 07 00 00 44 2b c0 8b 45 ec 05 8b 05 00 00 89 44 24 30 44 89 44 24 28 4d 8b c6 44 89 54 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EN_2147848905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EN!MTB"
        threat_id = "2147848905"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 c8 41 8d 40 82 41 ff c0 30 44 0c 28 41 83 f8 0c 72 ec}  //weight: 1, accuracy: High
        $x_1_2 = "WindowsProject_bin.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EN_2147848905_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EN!MTB"
        threat_id = "2147848905"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 c1 c1 f9 1f 29 ca 6b ca 36 29 c8 89 c2 89 d0 83 c0 38 44 89 c1 31 c1 48 8b 95 10 03 00 00 8b 85 04 03 00 00 48 98 88 0c 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_EN_2147848905_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.EN!MTB"
        threat_id = "2147848905"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 cb 49 89 d2 31 c9 4c 39 c9 73 ?? 48 89 c8 31 d2 49 f7 f2 41 8a 04 13 41 30 04 08 48 8b 05 ?? ?? ?? ?? 48 c1 e0 04 48 8d 4c 01 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_LKBI_2147897207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.LKBI!MTB"
        threat_id = "2147897207"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 85 c0 48 8b ce 48 0f 45 cb 48 8b d9 48 83 ef 01 75 [0-16] ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_LKBJ_2147897208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.LKBJ!MTB"
        threat_id = "2147897208"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c3 32 43 ff 48 ff c6 88 46 ff 48 39 fb 75 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_LKBL_2147897209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.LKBL!MTB"
        threat_id = "2147897209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "huaweioos.oss-ap-southeast-1.aliyuncs.com/success" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_HQ_2147898112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.HQ!MTB"
        threat_id = "2147898112"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 30 fa 80 70 0a fa 48 83 c0 14 4c 39 c0 75 f0}  //weight: 10, accuracy: High
        $x_10_2 = {80 30 1a 80 70 07 1a 48 83 c0 0e 49 39 c0 75 f0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_HQ_2147898112_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.HQ!MTB"
        threat_id = "2147898112"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8d 49 01 41 f7 e8 41 8b c8 41 ff c0 d1 fa 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 0f b6 4c 05 ?? 41 30 49 ?? 41 81 f8 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_LKBK_2147899613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.LKBK!MTB"
        threat_id = "2147899613"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 c3 02 c3 e9}  //weight: 1, accuracy: High
        $x_1_2 = {32 c3 c0 c8 31 e9}  //weight: 1, accuracy: High
        $x_1_3 = {aa 48 ff c9 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AMS_2147899656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AMS!MTB"
        threat_id = "2147899656"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 63 8d 20 03 00 00 48 03 f9 48 03 d9 41 ff c7 33 d2 49 8b c6 48 f7 f1 49 63 cf 48 3b c8}  //weight: 5, accuracy: High
        $x_5_2 = {41 0f b6 0c 00 30 08 48 8d 40 01 48 83 ea 01 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AE_2147900885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AE!MTB"
        threat_id = "2147900885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 0f b6 01 30 01 48 8d 49 01 41 0f b6 01 44 6b c0 ?? 41 80 c0 ?? 45 88 01 48 83 ea ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RI_2147903139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RI!MTB"
        threat_id = "2147903139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 95 7c ff ff ff 48 8b 45 f8 49 89 d1 41 b8 20 00 00 00 ba 18 00 00 00 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 85 c0 0f 94 c0 84 c0 74 24}  //weight: 1, accuracy: Low
        $x_1_2 = "/beacon.bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_GPC_2147904280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.GPC!MTB"
        threat_id = "2147904280"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "fc4883e4f0e8c8000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0" ascii //weight: 5
        $x_2_2 = "b0275728b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac4" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AMMC_2147905046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AMMC!MTB"
        threat_id = "2147905046"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 c2 83 e2 ?? 8a 54 15 ?? 32 14 07 88 14 01 48 ff c0 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_PNK_2147913613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.PNK!MTB"
        threat_id = "2147913613"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 6f 40 e0 48 8d 40 40 66 0f 6f ca 0f 57 c8 f3 0f 7f 48 a0 66 0f 6f ca f3 0f 6f 40 b0 0f 57 c2 f3 0f 7f 40 b0 f3 0f 6f 40 c0 0f 57 c8 f3 0f 7f 48 c0 66 0f 6f ca f3 0f 6f 40 d0 0f 57 c8 f3 0f 7f 48 d0 48 83 e9 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_HL_2147913851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.HL!MTB"
        threat_id = "2147913851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 c9 07 c1 7d 00 81 f1 97 57 23 b8 41 30 0c 06 69 c9 07 c1 7d 00 81 f1 97 57 23 b8 41 30 4c 06 01 48 83 c0 02 48 39 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_HL_2147913851_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.HL!MTB"
        threat_id = "2147913851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 0f b6 08 8b c3 99 41 f7 fa 48 63 c2 42 0f b6 14 38 2b ca 81 c1 ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 7d ?? ff c9 81 c9 ?? ?? ?? ?? ff c1 41 88 08 ff c3 49 ff c0 49 83 e9 01 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_JMR_2147914046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.JMR!MTB"
        threat_id = "2147914046"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 f7 fb 48 63 c2 0f b6 84 87 59 04 00 00 89 ca c1 ea 08 42 32 14 08 88 54 ae 02 48 8b 44 24 28 01 e8 99 f7 fb 48 63 c2 0f b6 84 87 58 04 00 00 42 32 0c 08 88 4c ae 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_HO_2147916215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.HO!MTB"
        threat_id = "2147916215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 08 41 8d 14 00 48 83 c0 01 31 ca 88 50 ff 4c 39 c8 75 eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_FB_2147918130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.FB!MTB"
        threat_id = "2147918130"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {8b 04 24 48 89 44 24 ?? 8b 0c 24 33 d2 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 0f be 0c 11 33 c8 8b c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a}  //weight: 15, accuracy: Low
        $x_10_2 = "fuuuuuccccckkkkkkmmmeeee" ascii //weight: 10
        $x_1_3 = "dsssssaaaaaiiiii" ascii //weight: 1
        $x_1_4 = "LoadResource" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "CreateFileA" ascii //weight: 1
        $x_1_7 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Cobaltstrike_NSK_2147918414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.NSK!MTB"
        threat_id = "2147918414"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c1 4c 89 c2 83 e1 07 48 c1 e1 03 48 d3 ea 41 30 54 05 00 48 83 c0 01 48 83 f8 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_ADG_2147918630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.ADG!MTB"
        threat_id = "2147918630"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F7daS.dll" ascii //weight: 1
        $x_1_2 = {80 74 05 cf fa 49 03 c4 48 83 f8 0d 72 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_ADG_2147918630_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.ADG!MTB"
        threat_id = "2147918630"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c0 89 44 24 30 8b 44 24 34 39 44 24 30 73 20 48 63 44 24 30 48 8b 4c 24 38 0f be 04 01 83 f0 32 48 63 4c 24 30 48 8b 54 24 38 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_PRD_2147918798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.PRD!MTB"
        threat_id = "2147918798"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 31 f0 42 88 44 3b 08 4c 89 f2 48 c1 fa 08 31 d0 4c 89 f2 48 c1 fa 10 31 d0 4c 89 f2 49 83 c6 01 48 c1 fa 18 31 d0 42 88 44 3b 08 49 83 c7 01 49 39 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_WQF_2147918829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.WQF!MTB"
        threat_id = "2147918829"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 04 24 0f b6 0a 48 83 c2 01 31 c8 49 83 c4 01 41 88 44 24 ff 4d 39 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_WFB_2147918833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.WFB!MTB"
        threat_id = "2147918833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 30 46 fe 41 8b 44 8d 08 41 31 44 95 08 41 8b 44 ad 08 41 8d 0c 00 43 31 4c 95 08 49 ff cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_FC_2147919054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.FC!MTB"
        threat_id = "2147919054"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 0f b6 c2 45 32 c9 45 03 c3 41 c1 e0 02 41 0f b6 c1 41 fe c1 41 03 c0 8a 0c 18 30 0a 48 ff c2 41 80 f9 04 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_ALJ_2147919396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.ALJ!MTB"
        threat_id = "2147919396"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8a 04 04 30 04 33 48 ff c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_RJS_2147919662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.RJS!MTB"
        threat_id = "2147919662"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 00 11 22 33 44 55 66 77 48 89 45 c8 48 b8 0f 05 90 90 c3 90 cc cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_GJ_2147919670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.GJ!MTB"
        threat_id = "2147919670"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 45 e8 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 49 89 c0 ba 00 00 00 00 b9 00 00 00 00 48 8b 05 19 6a 00 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_STG_2147919846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.STG!MTB"
        threat_id = "2147919846"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 89 f8 40 c0 ef 04 40 0f b6 ff 4c 8d 0d c5 c2 03 00 42 0f b6 3c 0f 48 83 fe 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_BCD_2147919861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.BCD!MTB"
        threat_id = "2147919861"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 0f b6 40 02 c3}  //weight: 1, accuracy: High
        $x_1_2 = {e8 81 fe ff ff 88 45 ff 80 7d ff 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_FEA_2147919948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.FEA!MTB"
        threat_id = "2147919948"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00 45 33 f6 41 8b fe 48 8b 48 60 8a 41 02 4c 8b 61 18 49 83 c4 20 84 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_FEM_2147920040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.FEM!MTB"
        threat_id = "2147920040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 c1 e9 1e 33 c1 69 c0 65 89 07 6c 41 03 c0 89 44 94 64 41 ff c0 48 ff c2 49 3b d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_FD_2147920075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.FD!MTB"
        threat_id = "2147920075"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 0f b6 c2 45 32 c9 45 03 c3 41 c1 e0 02 41 0f b6 c1 41 fe c1 41 03 c0 8a 0c 38 30 0a 48 ff c2 41 80 f9 04 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_KGF_2147925631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.KGF!MTB"
        threat_id = "2147925631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 0f af 83 98 00 00 00 8b 83 60 01 00 00 ff c8 31 83 88 01 00 00 48 8b 83 f8 00 00 00 41 8b d0 c1 ea 10 88 14 01 41 8b d0 ff 83 ac 00 00 00 48 63 8b ac 00 00 00 48 8b 83 f8 00 00 00 c1 ea 08 88 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_KGF_2147925631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.KGF!MTB"
        threat_id = "2147925631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 ea 45 31 db 41 89 f2 41 c1 e2 ?? 49 01 da 31 c0 41 0f b6 0c 82 30 0c 02 48 83 c0 01 48 83 f8 04 75}  //weight: 5, accuracy: Low
        $x_4_2 = {48 83 c2 01 49 89 c2 c0 e8 04 83 e0 0f 41 83 e2 ?? 48 c1 e0 04 4c 01 e0 42 0f b6 04 10 88 42 ff 48 39 d1 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_JGM_2147925640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.JGM!MTB"
        threat_id = "2147925640"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b ce 48 8b d7 0f 1f 44 00 00 80 31 ac 48 ff c1 48 ff ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_KAU_2147927696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.KAU!MTB"
        threat_id = "2147927696"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 20 48 8d 44 24 30 48 8b 7c 24 20 48 8b f0 b9 07 16 05 00 f3 a4 4c 8d 4c 24 28 41 b8 20 00 00 00 ba 07 16 05 00 48 8b 4c 24 20 ff ?? ?? ?? ?? ?? ff 54 24 20 48 8b 8c 24 40 16 05 00 48 33 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_BPD_2147927712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.BPD!MTB"
        threat_id = "2147927712"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8d 44 24 40 48 83 7c 24 58 0f 4c 0f 47 44 24 40 48 8d 8d b0 02 00 00 33 d2 49 8b c1 49 f7 f4 48 03 d1 48 8d 8d d0 02 00 00 48 83 bd e8 02 00 00 0f 48 0f 47 8d d0 02 00 00 43 0f b6 04 08 32 02 42 88 04 09 49 ff c1 4c 3b 4c 24 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_MCH_2147928165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.MCH!MTB"
        threat_id = "2147928165"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 c9 48 8d 95 20 03 00 00 48 03 d1 0f b6 0a 41 88 0b 44 88 02 45 02 03 41 0f b6 d0 44 0f b6 84 15 20 03 00 00 45 30 02 49 ff c2 48 83 eb 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AAS_2147928218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AAS!MTB"
        threat_id = "2147928218"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 89 d1 4d 69 c9 39 8e e3 38 49 c1 e9 22 45 01 c9 47 8d 0c c9 41 89 d2 45 29 ca 4c 8b 8d f8 07 00 00 47 0f b6 0c 11 45 32 0c 10 4c 8d 05 63 97 04 00 46 88 0c 02 ff c2 83 fa 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DMZ_2147928265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DMZ!MTB"
        threat_id = "2147928265"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 19 41 88 04 19 44 88 14 19 41 0f b6 0c 19 49 03 ca 0f b6 c1 8a 0c 18 49 8b c6 49 83 7e 18 0f 76 03 49 8b 06 30 0c 02 41 ff c0 48 ff c2 49 63 c0 48 3b 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_DMH_2147928266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.DMH!MTB"
        threat_id = "2147928266"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 63 c3 41 0f b6 04 10 88 04 17 45 88 1c 10 48 8b 54 24 30 0f b6 0c 17 41 0f b6 04 10 48 03 c8 0f b6 c1 44 0f b6 04 10 49 8b ce 49 83 7e 18 0f 76 03 49 8b 0e 45 30 04 09 41 ff c2 49 ff c1 49 63 c2 49 3b 47 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_GOP_2147928824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.GOP!MTB"
        threat_id = "2147928824"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 48 8d 52 01 49 83 f9 1c 49 0f 45 c9 41 ff c0 42 0f b6 04 11 4c 8d 49 01 30 42 ff 49 63 c0 48 3b c3 72 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AUJ_2147931768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.AUJ!MTB"
        threat_id = "2147931768"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\Cobalt Fud" ascii //weight: 1
        $x_1_2 = "Documents\\buffer.txt" ascii //weight: 1
        $x_1_3 = "Result of executed code" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_OJU_2147945071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike.OJU!MTB"
        threat_id = "2147945071"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f1 e8 ?? ?? ?? ?? 48 83 fa ?? 75 ?? 8b 08 ba ?? ?? ?? ?? 31 d1 8b 40 ?? ba ?? ?? ?? ?? 31 d0 09 c8 0f 84 ?? ?? ?? ?? 0f 1f 80 ?? ?? ?? ?? 48 83 7c 24 ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobaltstrike_AMTB_2147959485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltstrike!AMTB"
        threat_id = "2147959485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c echo dAcBAloYhKlSJAw>" ascii //weight: 1
        $x_1_2 = "EastonHammes" ascii //weight: 1
        $x_1_3 = "NapoleonFunk" ascii //weight: 1
        $x_1_4 = "MarielaSchuster" ascii //weight: 1
        $x_1_5 = "SamDooley" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

