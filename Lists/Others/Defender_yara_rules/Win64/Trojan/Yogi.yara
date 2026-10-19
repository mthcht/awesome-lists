rule Trojan_Win64_Yogi_NY_2147973372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.NY!MTB"
        threat_id = "2147973372"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 44 24 10 48 8b 5c 24 18 48 89 e2 e8 ?? ?? ?? ?? 48 89 31 48 8b 66 38 48 83 ec 10 48 83 e4 f0 48 89 7c 24 08 48 8b 7f 08 48 29 d7 48 89 3c 24 e8 ?? ?? ?? ?? 48 8b 0d 9e 3d 5d 00 65 48 8b 09 48 8b 7c 24 08 48 8b 77 08 48 2b 34 24 48 89 39 48 89 f4 89 44 24 20}  //weight: 2, accuracy: Low
        $x_2_2 = {48 89 54 24 20 88 44 24 1f 48 8b 05 63 a5 5c 00 48 89 04 24 48 8d 82 20 05 00 00 48 89 44 24 08 e8 ?? ?? ?? ?? 45 0f 57 ff 4c 8b 35 03 02 61 00 65 4d 8b 36 4d 8b 36 0f b6 44 24 1f 84 c0}  //weight: 2, accuracy: Low
        $x_1_3 = "NewCBCDecrypter" ascii //weight: 1
        $x_1_4 = "formatBase10" ascii //weight: 1
        $x_1_5 = "stringremoveexec: hangupkilledlistensocket" ascii //weight: 1
        $x_1_6 = "//fakecorp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yogi_GVA_2147976307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.GVA!MTB"
        threat_id = "2147976307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.amtppol" ascii //weight: 1
        $x_1_2 = "main..inittask" ascii //weight: 1
        $x_1_3 = "main.Ncfsxqiifgcfbdy" ascii //weight: 1
        $x_1_4 = "main.jdzyznjfpka" ascii //weight: 1
        $x_1_5 = "main.pfdviozmtpnsvegtsw" ascii //weight: 1
        $x_1_6 = "main.(*TIOAS).zbadbpulk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yogi_SI_2147976750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.SI!MTB"
        threat_id = "2147976750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {ff 15 7d d5 00 00 be 01 00 00 00 48 8d 0d b9 4d 01 00 44 8b c6 89 05 d0 92 01 00 33 d2 ff 15 78 d5 00 00 48 89 05 b9 92 01 00 48 85 c0 0f 84 8b 01 00 00 8b 15 b2 92 01 00 48 8d 88 00 10 00 00 4c 8d 4c 24 48 48 89 0d a7 92 01 00 41 b8 08 00 00 00 89 7c 24 48 ff 15 c7 d4 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {0f 10 05 0f 4e 01 00 0f b7 05 20 4e 01 00 45 33 c9 48 89 7c 24 30 45 33 c0 0f 11 01 ba 00 00 00 80 89 7c 24 28 f2 0f 10 05 f9 4d 01 00}  //weight: 3, accuracy: High
        $x_1_3 = "colorui.dll" ascii //weight: 1
        $x_1_4 = "LaunchColorCpl" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yogi_A_2147977949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.A!MTB"
        threat_id = "2147977949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {c7 45 c7 48 8b 44 24 be 0e 00 00 00 c7 45 cb 30 c7 00 00 c7 45 cf 00 00 00 31 66 c7 45 d3 c0 c3}  //weight: 6, accuracy: High
        $x_4_2 = {4e 8d 04 10 0f be c8 6b d1 11 48 ff c0 41 02 d1 42 32 14 03 41 88 10 49 3b c3 72 e4}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yogi_A_2147977949_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.A!MTB"
        threat_id = "2147977949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {41 8b d6 41 bf ?? ?? 00 00 69 c0 ?? ?? ?? ?? 41 03 c7 8b c8 c1 e9 ?? 32 4c 14 30 88 4c 15 88 48 ff c2 48 83 fa ?? 72}  //weight: 30, accuracy: Low
        $x_20_2 = {c7 44 24 3c cc 00 e1 00 c7 44 24 40 28 00 2e 00 c7 44 24 44 f8 00 c4 00}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yogi_ARA_2147978982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.ARA!MTB"
        threat_id = "2147978982"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {49 8b 06 88 14 30 48 ff c6 49 3b f4 72 89}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yogi_ARA_2147978982_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.ARA!MTB"
        threat_id = "2147978982"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Kernel base leaks" ascii //weight: 2
        $x_2_2 = "--print-timings" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yogi_B_2147979312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.B!MTB"
        threat_id = "2147979312"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {c7 44 24 68 5b 57 45 61 c7 44 24 6c 47 42 42 5d c7 44 24 70 40 46 7f 53 66 c7 44 24 74 5b 5c}  //weight: 20, accuracy: High
        $x_10_2 = {8a 44 0c 50 34 32 88 44 0c 60 48 ff c1 48 83 f9 0c 72 ed 48 8d 54 24 60 40 88 74 24 6c 48 8d 4d a0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yogi_C_2147980022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.C!MTB"
        threat_id = "2147980022"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {b8 44 50 41 50 33 45 c0 0f b6 4d c4 83 f1 49 09 c1 0f 84 f3 01 00 00}  //weight: 15, accuracy: High
        $x_10_2 = {45 31 c9 ff 15 ?? ?? ?? ?? 48 83 f8 ff 74 36 48 89 c6 c7 45 c0 00 00 00 00 48 c7 44 24 20 00 00 00 00 48 8d 95 f0 23 00 00 4c 8d 4d c0 48 89 c1 41 b8 72 00 00 00 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yogi_AA_2147980320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yogi.AA!MTB"
        threat_id = "2147980320"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {8b 44 24 18 05 ?? ?? ?? ?? 0f b6 00 0f b6 c0 01 44 24 1c 83 44 24 18}  //weight: 15, accuracy: Low
        $x_5_2 = {8b 04 24 8d 50 ?? 89 14 24 8b 54 24 0c 88 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

