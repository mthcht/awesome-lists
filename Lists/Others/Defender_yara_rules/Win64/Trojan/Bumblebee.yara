rule Trojan_Win64_Bumblebee_KR_2147819945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.KR!MSR"
        threat_id = "2147819945"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CeQwySdM" ascii //weight: 2
        $x_2_2 = "KQRN71" ascii //weight: 2
        $x_2_3 = "Mfr07A74" ascii //weight: 2
        $x_2_4 = "QXYuok660" ascii //weight: 2
        $x_2_5 = "pvunjSjVYP" ascii //weight: 2
        $x_1_6 = "GetStdHandle" ascii //weight: 1
        $x_1_7 = "ConnectNamedPipe" ascii //weight: 1
        $x_1_8 = "CreateFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_DIU_2147819955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.DIU!MTB"
        threat_id = "2147819955"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {42 0f b6 04 01 c1 e0 18 89 f2 21 c2 31 c6 09 f2 48 8b 4c 24 30 8b 44 24 24 41 89 c0 42 89 14 81}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_CMN_2147819997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.CMN!MTB"
        threat_id = "2147819997"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {48 03 ca 48 8d 51 20 e8 ?? ?? ?? ?? 84 c0 75 24 ff c3 48 63 cb 48 8b 85 ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 48 2b c2 48 c1 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_CRPT_2147820012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.CRPT!MTB"
        threat_id = "2147820012"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 83 a8 03 00 00 48 63 83 3c 05 00 00 48 63 93 38 05 00 00 41 8b 0c 80 41 31 0c 90 8b 8b 4c 05}  //weight: 1, accuracy: High
        $x_1_2 = {48 63 93 b0 04 00 00 48 8b 4b ?? 48 8b 43 78 8a 14 0a 41 32 14 01 48 8b 83 ?? ?? ?? ?? 41 88 14 01}  //weight: 1, accuracy: Low
        $x_1_3 = {49 8b 8a 98 02 00 00 48 09 81 80 02 00 00 42 8a 0c 37 2a 8c 24 80 00 00 00 32 4c 24 78 49 8b 42 78 41 88 0c 06}  //weight: 1, accuracy: High
        $x_1_4 = {48 ff 80 70 04 00 00 48 8b 83 18 01 00 00 48 8b 8b c0 03 00 00 48 35 ?? ?? ?? ?? 48 01 81 b0 03 00 00 8b 83 2c 04}  //weight: 1, accuracy: Low
        $x_1_5 = {48 63 55 1b 41 03 c9 49 33 95 20 04 00 00 45 8b 85 b0 04 00 00 49 0f af 95 90 01 00 00 4d 23 c2 4d 33 45 08}  //weight: 1, accuracy: High
        $x_1_6 = {49 8b 4e 20 49 8b 46 40 8a 14 0a 42 32 14 00 49 8b 46 70 41 88 14 00}  //weight: 1, accuracy: High
        $x_1_7 = {48 63 87 c4 05 00 00 48 63 97 c0 05 00 00 41 8b 0c 80 41 31 0c 90 8b 8f d4 05 00 00 23 cb}  //weight: 1, accuracy: High
        $x_1_8 = {49 8b 46 70 41 ff c1 48 63 55 e8 49 8b 8e b0 00 00 00 49 0f af 8e 30 03 00 00 48 0f af c1 48 63 4d f4 49 89 46 70 49 0b 96 88 01 00 00 48 03 ca 49 63 c1 48 3b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Bumblebee_EX_2147826293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.EX!MTB"
        threat_id = "2147826293"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 44 ?? ?? ff 15 ?? ?? ?? ?? 44 ?? ?? 33 ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 33 ?? 41 ?? ?? ?? ?? ?? 48 ?? ?? ?? 41 ?? ?? ?? ?? ?? bf ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4c ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 ?? ?? 44 ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? 89 ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? 8b ?? ?? 81 ?? ?? ?? ?? ?? 3b ?? 0f ?? ?? ?? ?? ?? 8b ?? ?? 8b ?? ?? 81 ?? ?? ?? ?? ?? 3b ?? 0f ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 ?? ?? 81 ?? ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? 83 ?? ?? ?? 8b ?? ?? 89 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 81 ?? ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? ?? 8b ?? ?? 8b ?? ?? 83}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b 45 ff 81 ?? ?? ?? ?? ?? 44 ?? ?? ?? 41 ?? ?? ?? 8b ?? ?? 41 ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? 83 ?? ?? 44 ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? 45 ?? ?? 44 ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 8b ?? ?? 41 ?? ?? ?? ?? ?? ?? 8b ?? ?? 81 ?? ?? ?? ?? ?? 8b ?? ?? 44 ?? ?? ?? 81 ?? ?? ?? ?? ?? 45 ?? ?? 89 ?? ?? 44 ?? ?? ?? 8b ?? ?? 41 ?? ?? ?? 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_PA_2147829552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.PA!MTB"
        threat_id = "2147829552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 81 b8 03 00 00 49 8b [0-2] 08 49 8b [0-2] 70 02 00 00 48 69 88 40 01 00 00 [0-4] 48 31 8a d0 03 00 00 4d 8b [0-2] 58 04 00 00 49 63 [0-2] 0c 06 00 00 49 63 [0-2] 08 06 00 00 41 8b 0c 80 41 31 0c 90 41 8b [0-2] 1c 06 00 00 23 ?? 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "OboXbQXMPB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_PA_2147829552_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.PA!MTB"
        threat_id = "2147829552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 0f b6 49 ?? 41 0f b6 14 00 49 83 c0 04 49 8b 81 ?? ?? ?? ?? 0f af d1 49 63 49 ?? 88 14 01 b8 ?? ?? ?? ?? 41 2b 41 ?? 41 01 81 ?? ?? ?? ?? b8 ?? ?? ?? ?? 41 8b}  //weight: 10, accuracy: Low
        $x_1_2 = {41 33 ca 41 ff 41 ?? 2b c1 41 01 41 ?? 41 8b 41 ?? 83 f0 01 83 c0 df 03 c2 41 2b 91 ?? ?? ?? ?? 41 01 81 ?? ?? ?? ?? 83 ea ?? 41 8b 41}  //weight: 1, accuracy: Low
        $x_1_3 = {41 8b ca 41 33 89 ?? ?? ?? ?? 41 ff 41 50 2b c1 41 01 41 ?? 41 8b 41 ?? 83 f0 01 83 c0 df 03 c2 41 2b 91 ?? ?? ?? ?? 41 01 81 ?? ?? ?? ?? 83 ea ?? 41 8b 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Bumblebee_PB_2147829558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.PB!MTB"
        threat_id = "2147829558"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {41 8b 0c 80 41 31 0c 90 41 8b [0-4] 00 00 23 ?? 7d}  //weight: 4, accuracy: Low
        $x_4_2 = {41 8b 0c 80 41 31 0c 90 41 8b 8e [0-4] 00 00 41 23 ce 7d}  //weight: 4, accuracy: Low
        $x_1_3 = "OboXbQXMPB" ascii //weight: 1
        $x_1_4 = "LOG17fv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Bumblebee_FC_2147829631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.FC!MTB"
        threat_id = "2147829631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af c1 8b 4d f3 48 98}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fb 0b c8 29 4d 6f 8b 4d eb 8b 45 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_FE_2147829632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.FE!MTB"
        threat_id = "2147829632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 89 81 c8 05 00 00 49 8b 81 a8 00 00 00 48 8b 88 a8 02 00 00 48 81 e9 08 0f 00 00 49 63 c0 48 3b c1}  //weight: 1, accuracy: High
        $x_1_2 = {41 2b c8 41 ff c2 0f b6 14 18 d3 e2}  //weight: 1, accuracy: High
        $x_1_3 = {49 8b 4a 10 48 8b 41 08 48 31 41 38 49 8b 42 10 48 ff 48 08}  //weight: 1, accuracy: High
        $x_1_4 = {48 89 90 c0 00 00 00 48 8b 8b a8 00 00 00 48 8b 81 88 02 00 00 48 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Bumblebee_FG_2147829641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.FG!MTB"
        threat_id = "2147829641"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 43 10 bf 01 00 00 00 48 8b 93 a8 00 00 00 49 8b 88 20 01 00 00 48 33 cd}  //weight: 1, accuracy: High
        $x_1_2 = {4c 89 64 24 70 4c 2b f1 43 8a 0c 0c 2a 4c 24 68 32 4c 24 60 49 8b 43 58 41 88 0c 01}  //weight: 1, accuracy: High
        $x_1_3 = {49 8b 87 c8 01 00 00 49 2b 47 60 49 31 87 58 02 00 00 49 8b 87 18 02 00 00 48 0f af c1 49 89 87 18 02 00 00 49 8b 87 20 03 00 00 48 35}  //weight: 1, accuracy: High
        $x_1_4 = {48 31 8a 08 04 00 00 48 8b 85 78 06 00 00 48 89 45 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Bumblebee_SM_2147831369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.SM!MTB"
        threat_id = "2147831369"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 08 55 56 57 41 54 41 55 41 56 41 57 48 8d 6c 24 d9 48 81 ec b0 00 00 00 ff 15 ?? ?? ?? ?? bb ?? ?? ?? ?? 33 d2 48 8b c8 44 8b c3 ff 15 ?? ?? ?? ?? 44 8b c3 33 d2 48 8b c8 48 89 05 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = "UdIPax9H" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_KU_2147831370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.KU!MTB"
        threat_id = "2147831370"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 83 38 03 00 00 48 63 83 d4 04 00 00 48 63 93 d0 04 00 00 48 c7 83 d0 00 00 00 a4 c8 73 01 41 8b 0c 80 41 31 0c 90 8b 8b e4 04 00 00 41 23 cb 7d 07}  //weight: 1, accuracy: High
        $x_1_2 = {49 8b 4d 18 49 8b 45 30 49 63 95 ?? ?? ?? ?? 8a 14 0a 42 32 14 08 49 8b 45 60 41 88 14 01 41 69 8d ?? ?? ?? ?? ?? ?? ?? ?? 41 8b 85 e8 01 00 00 05 7e 01 00 00 3b c1 73 11}  //weight: 1, accuracy: Low
        $x_1_3 = "HSdOt60362" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_DSN_2147831549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.DSN!MTB"
        threat_id = "2147831549"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 84 24 90 00 00 00 81 c5 5a 2b 00 00 49 8b 88 08 03 00 00 48 8b 81 d0 01 00 00 48 35 45 9a 10 00 49 89 80 60 01 00 00 48 c7 81 a8 03 00 00 06 ad ee 03 49 8b 88 28 03 00 00 48 8b 81 f8 00 00 00 48 01 41 40 49 8b 80 28 03 00 00 48 ff 88 f8 00 00 00 49 8b 80 a0 03 00 00 49 8b 90 18 03 00 00 48 8b 88 d0 01 00 00 48 81 c1 77 16 00 00 48 01 8a 20 01 00 00 81 ef ee 06 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "QUk024" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MKO_2147831645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MKO!MTB"
        threat_id = "2147831645"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 d3 c8 49 63 81 ?? ?? ?? ?? 41 ba ?? ?? ?? ?? 44 01 04 82 45 8b c2 49 8b 81 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 41 3b ca 76 33 4d 8d 91 ?? ?? ?? ?? 49 8b 81 ?? ?? ?? ?? 41 ff c0 4c 31 ?? ?? ?? ?? ?? 49 8b 81 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 49 63 c0 48 3b c2 72}  //weight: 1, accuracy: Low
        $x_1_2 = "LOG17fv" ascii //weight: 1
        $x_1_3 = "YcWr4qI8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_SA_2147833143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.SA!MTB"
        threat_id = "2147833143"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 43 28 48 8b 8b ?? ?? ?? ?? 48 2d ?? ?? ?? ?? 48 89 83 ?? ?? ?? ?? 48 c7 c0 ?? ?? ?? ?? 48 2b 83 ?? ?? ?? ?? 48 01 41 ?? 48 8b 8b ?? ?? ?? ?? 48 8b 81 ?? ?? ?? ?? 48 31 43 ?? 4a 8d 04 2a 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 09 ab ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = "EssUr365fOL1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_SS_2147833228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.SS!MTB"
        threat_id = "2147833228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 7f 48 33 c1 89 45 7f 48 63 45 6f 49 8b 95 e8 00 00 00 48 63 4d f7 48 0f af d0 49 63 c1 48 33 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_SB_2147833418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.SB!MTB"
        threat_id = "2147833418"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 88 20 03 00 00 81 e9 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 49 8b 83 ?? ?? ?? ?? 4c ?? ?? ?? ?? ?? ?? 49 8b 8b ?? ?? ?? ?? 48 8b 81 ?? ?? ?? ?? 48 33 c7 48 89 81 ?? ?? ?? ?? 49 8b 83}  //weight: 1, accuracy: Low
        $x_1_2 = "JzGbEU8m" ascii //weight: 1
        $x_1_3 = "QUk024" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_WEL_2147834497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.WEL!MTB"
        threat_id = "2147834497"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 ea 08 01 83 ?? ?? ?? ?? 48 8b 83 ?? ?? ?? ?? 88 14 01 ff 43 ?? 48 63 4b 74 48 8b 83 ?? ?? ?? ?? 44 88 04 01 8b 83 ?? ?? ?? ?? 8b 93 ?? ?? ?? ?? 35 40 33 0e 00 0f af 43 ?? ff 43 ?? 01 93 ?? ?? ?? ?? 33 43 ?? 83 f0 01 89 43 ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 5, accuracy: Low
        $x_1_2 = "ZARSY62" ascii //weight: 1
        $x_1_3 = "RJVQa11Y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_ZAA_2147834572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.ZAA!MTB"
        threat_id = "2147834572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 8b d0 c1 ea 08 88 14 01 ff 43 ?? 48 63 4b ?? 48 8b 83 ?? ?? ?? ?? 44 88 04 01 ff 43 ?? 8b 43 ?? 2d ?? ?? ?? ?? 31 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 8b 43 ?? 33 43 ?? 83 f0 01 89 43 ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 5, accuracy: Low
        $x_1_2 = "BasicLoad" ascii //weight: 1
        $x_1_3 = "DWJMR1481" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_IND_2147834783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.IND!MTB"
        threat_id = "2147834783"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 43 68 8d 04 4d ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8b 43 ?? 48 8b 8b ?? ?? ?? ?? 31 04 11 48 83 c2 04 8b 83 c0 00 00 00 01 43 ?? 8b 43 08 2b 83 ?? ?? ?? ?? 2d ?? ?? ?? ?? 09 83 ?? ?? ?? ?? 48 81 fa ?? ?? ?? ?? 7c}  //weight: 5, accuracy: Low
        $x_1_2 = "csvcrun" ascii //weight: 1
        $x_1_3 = "Rjjw9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_WKX_2147834860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.WKX!MTB"
        threat_id = "2147834860"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b d0 b8 01 00 00 00 c1 ea 08 2b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 8b 43 ?? 01 43 ?? 8b 43 ?? 8b 8b ?? ?? ?? ?? ff c1 0f af c1 89 43 ?? 48 63 4b ?? 48 8b 83 ?? ?? ?? ?? 88 14 01 ff 43 ?? 48 63 4b ?? 48 8b 83 ?? ?? ?? ?? 44 88 04 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_IRM_2147834937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.IRM!MTB"
        threat_id = "2147834937"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f af c1 89 43 ?? 8b 83 ?? ?? ?? ?? 05 ?? ?? ?? ?? 01 43 ?? 8b 8b ?? ?? ?? ?? 8d 41 ?? 31 43 ?? 8d 04 4d ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8b 43 ?? 48 8b 8b ?? ?? ?? ?? 42 31 04 ?? 49 83 ?? 04 8b 83 ?? ?? ?? ?? 01 43 ?? 8b 43 08 2b 83 ?? ?? ?? ?? 2d ?? ?? ?? ?? 09 83 ?? ?? ?? ?? 49 81 ?? ?? ?? ?? ?? 7c}  //weight: 5, accuracy: Low
        $x_1_2 = "SendData" ascii //weight: 1
        $x_1_3 = "Joq975" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_CSC_2147835009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.CSC!MTB"
        threat_id = "2147835009"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f af c1 89 43 ?? 8b 83 ?? ?? ?? ?? 05 ?? ?? ?? ?? 01 43 ?? 8b 8b ?? ?? ?? ?? 8d 41 ?? 31 43 ?? 8d 04 4d ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 48 8b 8b ?? ?? ?? ?? 8b 43 ?? 42 31 04 31 49 83 c6 ?? 8b 8b ?? ?? ?? ?? 01 4b ?? 8b 4b ?? 2b 8b ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 09 8b ?? ?? ?? ?? 49 81 fe ?? ?? ?? ?? 7c}  //weight: 5, accuracy: Low
        $x_1_2 = "SendData" ascii //weight: 1
        $x_1_3 = "Joq975" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_IPL_2147835416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.IPL!MTB"
        threat_id = "2147835416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 48 8b 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 45 31 04 01 49 83 c1 04 8b 0d ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 44 03 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af c1 8b 0d ?? ?? ?? ?? 33 ca 89 05 ?? ?? ?? ?? 8b 05 6e 5d 05 00 05 ?? ?? ?? ?? 03 c8 b8 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_VIA_2147835494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.VIA!MTB"
        threat_id = "2147835494"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 84 24 c8 ?? ?? ?? 83 c0 01 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 39 84 24 ?? ?? ?? ?? 7d ?? 48 63 84 24 ?? ?? ?? ?? 44 0f b6 44 04 ?? 8b 84 24}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 2a 00 00 00 f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 41 8b d0 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 88 14 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_TR_2147836205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.TR!MTB"
        threat_id = "2147836205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 8b 84 00 00 00 88 14 01 ff 83 84 00 00 00 8b 83 04 01 00 00 03 43 0c 33 43 64 48 63 8b 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_FB_2147836947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.FB!MTB"
        threat_id = "2147836947"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoOZz46Px" ascii //weight: 1
        $x_1_2 = "TfLXv12k" ascii //weight: 1
        $x_1_3 = "VRIZS6p" ascii //weight: 1
        $x_5_4 = "cmfgutil" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_ZMY_2147837401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.ZMY!MTB"
        threat_id = "2147837401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 01 4b ?? 8b 43 ?? 48 8b 8b ?? ?? ?? ?? 35 ?? ?? ?? ?? 09 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 33 83 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 2b 43 ?? 2d ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 8b 43 ?? 31 04 11 48 83 c2 ?? 8b 83 ?? ?? ?? ?? 01 43 ?? 8b 83 ?? ?? ?? ?? 01 43 ?? 48 81 fa ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_QMV_2147840748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.QMV!MTB"
        threat_id = "2147840748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c1 41 8b d0 41 89 81 ?? ?? ?? ?? 41 8b 81 ?? ?? ?? ?? 35 ?? ?? ?? ?? c1 ea ?? 41 29 81 ?? ?? ?? ?? 49 63 49 ?? 49 8b 81 ?? ?? ?? ?? 88 14 01 41 8b d0 41 ff 41 ?? 41 8b 41 ?? 41 8b 89 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? c1 ea ?? 0f af c1 41 89 41 ?? 41 8b 01 ff c8}  //weight: 1, accuracy: Low
        $x_1_2 = "UzEPx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_ZRR_2147840904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.ZRR!MTB"
        threat_id = "2147840904"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c1 49 63 49 ?? c1 ea ?? 41 89 01 49 8b 81 ?? ?? ?? ?? 88 14 01 41 ff 41 ?? 49 63 49 ?? 49 8b 81 ?? ?? ?? ?? 44 88 04 01 41 8b 41 ?? 41 ff 41 ?? 8d 88 ?? ?? ?? ?? 33 c8 41 8b 81 ?? ?? ?? ?? 41 89 49 ?? 41 29 81 ?? ?? ?? ?? 49 81 fa ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = "Condensed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_IRZ_2147841377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.IRZ!MTB"
        threat_id = "2147841377"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 04 31 48 83 c6 ?? 8b 43 ?? 2d ?? ?? ?? ?? 01 43 ?? 8b 83 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? 8b 53 ?? 35 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 53 ?? 09 93 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? 31 43 ?? 8b 83 ?? ?? ?? ?? ff c8 01 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 01 43 ?? 48 81 fe ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MBB_2147841587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MBB!MTB"
        threat_id = "2147841587"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 41 8d 81 ?? ?? ?? ?? 44 33 c0 89 0d ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 44 89 05 ?? ?? ?? ?? 31 14 03 48 83 c3 ?? 44 8b 05 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 05 ?? ?? ?? ?? 44 8b 0d ?? ?? ?? ?? 41 2b d0 03 d0 41 81 c0 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 44 03 c2 41 2b c1 89 15 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = "init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MBC_2147842513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MBC!MTB"
        threat_id = "2147842513"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 04 11 48 83 c2 ?? 41 8b 89 ?? ?? ?? ?? 41 8b 81 ?? ?? ?? ?? 03 c1 35 ?? ?? ?? ?? 41 29 41 ?? 41 8b 41 ?? 83 e8 ?? 41 01 41 ?? 41 8b 81 ?? ?? ?? ?? 33 c1 35 ?? ?? ?? ?? 41 29 81 ?? ?? ?? ?? 41 8b 81 ?? ?? ?? ?? 41 01 81 ?? ?? ?? ?? 41 8b 81 ?? ?? ?? ?? 41 29 41 ?? 48 81 fa ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_ZMH_2147844197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.ZMH!MTB"
        threat_id = "2147844197"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d6 09 15 ?? ?? ?? ?? 44 31 04 03 48 83 c3 04 48 8b 05 ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 44 03 80 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 35 ?? ?? ?? ?? 44 89 05 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 48 81 fb ?? ?? ?? ?? 7c ?? 65 00 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 48 8b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_WEJ_2147844659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.WEJ!MTB"
        threat_id = "2147844659"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 f7 f1 43 89 14 86 41 0f b6 03 4c 8b 47 ?? 0f b7 4c 45 ?? 41 8b c1 99 45 03 cd f7 f9 43 0f b6 04 03 4d 03 dd 66 03 d0 66 42 31 14 43 4c 8b 84 24 ?? ?? ?? ?? 45 3b cc 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_KKK_2147845420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.KKK!MTB"
        threat_id = "2147845420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 83 c1 04 01 43 ?? 8b 43 ?? 2b 43 ?? ?? ?? ?? ?? 11 01 83 ?? ?? ?? ?? 8b 43 ?? 35 ?? ?? ?? ?? 29 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 01 43 ?? 8b 43 ?? 2b 83 ?? ?? ?? ?? 05 ?? ?? ?? ?? 09 83 ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "bYXjdERymsFY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MYT_2147847230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MYT!MTB"
        threat_id = "2147847230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 8b 4c 24 ?? 83 c1 ?? 48 63 c9 33 d2 4c 8b 84 24 ?? ?? ?? ?? 49 f7 34 c8 8b 4c 24 ?? 83 c1 ?? 48 63 c9 48 8b 94 24 ?? ?? ?? ?? 48 89 04 ca 0f b7 05 ?? ?? ?? ?? 66 ff c0 66 89 05 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_VIO_2147848698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.VIO!MTB"
        threat_id = "2147848698"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 0f af cd 48 01 8a ?? ?? ?? ?? 48 8b cb 48 8b 97 ?? ?? ?? ?? 48 0f af cb 48 8b 82 ?? ?? ?? ?? 48 0f af c1 48 89 82 ?? ?? ?? ?? eb 4b 48 8b 87 ?? ?? ?? ?? 48 81 b0 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 87 c8 02 00 00 48 c7 80 ?? ?? ?? ?? ?? ?? ?? ?? 48 63 87 28 05 00 00 3d 00 0e 24 00 7d 16 48 8b 8f ?? ?? ?? ?? 48 8b d0 41 8a 00 88 04 0a ff 87 ?? ?? ?? ?? 49 ff c8 4c 3b 87 ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_VIN_2147848828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.VIN!MTB"
        threat_id = "2147848828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 03 d5 48 8b 4f ?? 48 8b 47 ?? 8a 14 0a 41 32 14 01 48 8b 87 ?? ?? ?? ?? 41 88 14 01 33 d2 48 63 8f ?? ?? ?? ?? 4c 03 cd 4c 8b 87 a8 02 00 00 48 81 c1 86 d6 ff ff 49 8b 80 ?? ?? ?? ?? 48 03 c1 48 63 4f ?? 48 f7 f1 89 97 08 05 00 00 49 81 80 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 87 a8 02 00 00 48 8b 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_VIK_2147848829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.VIK!MTB"
        threat_id = "2147848829"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8d 34 0b 4c 8b 74 24 40 4d 2b e3 48 81 c2 ?? ?? ?? ?? 4d 8b cb 48 2b f9 49 8b 8a 98 02 00 00 48 8b 81 ?? ?? ?? ?? 48 0f af c2 48 89 81 ?? ?? ?? ?? 49 81 82 ?? ?? ?? ?? ?? ?? ?? ?? 41 8a 0c 34 2a 4c 24 ?? 32 4c 24 ?? 49 8b 42 ?? 88 0c 06 83 fb 08 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_VIL_2147848830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.VIL!MTB"
        threat_id = "2147848830"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 80 c1 0a ff c7 22 d1 85 c0 74 10 49 8b 4a ?? 8a 04 0e 02 c0 0a c2 88 04 0e eb 07 49 8b 42 ?? 88 14 06 49 8b 82 ?? ?? ?? ?? 48 31 68 ?? 49 8b 82 ?? ?? ?? ?? 48 0f af 05 ?? ?? ?? ?? 49 8b 92 08 03 00 00 49 89 82 ?? ?? ?? ?? 49 8b 82 ?? ?? ?? ?? 48 8b 88 ?? ?? ?? ?? 48 81 c1 ?? ?? ?? ?? 48 31 8a ?? ?? ?? ?? 49 8b 82 c8 03 00 00 48 8b 88 ?? ?? ?? ?? 48 81 e9 ?? ?? ?? ?? 48 63 c7 48 3b c1 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_VIQ_2147848895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.VIQ!MTB"
        threat_id = "2147848895"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 3b c6 0f 8d ?? ?? ?? ?? 4c 8b 6c 24 ?? 4c 8d 14 03 4c 2b eb 4c 8b c3 48 2b f0 0f b6 0d ?? ?? ?? ?? 49 8b 83 ?? ?? ?? ?? 48 0f af cf 48 09 88 ?? ?? ?? ?? 43 8a 0c 2a 2a 4c 24 60 32 4c 24 58 49 8b 43 58 41 88 0c 02 83 fd 08 0f 84 ?? ?? ?? ?? 49 8b 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_VIR_2147848896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.VIR!MTB"
        threat_id = "2147848896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8d 1c 08 4d 2b e8 4c 89 1c 24 49 8b f0 4c 89 ac 24 ?? ?? ?? ?? 44 0f b7 44 24 ?? 48 2b d9 43 8a 0c 2b 2a 8c 24 ?? ?? ?? ?? 32 8c 24 ?? ?? ?? ?? 49 8b 41 ?? 41 88 0c 03 83 ff 08 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_RNQ_2147848970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.RNQ!MTB"
        threat_id = "2147848970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 2b eb 4d 8b cb 4c 2b c1 49 8b 4a ?? 48 8b 81 ?? ?? ?? ?? 49 0f af c6 48 29 41 ?? 42 8a 0c 2f 2a 4c 24 ?? 32 4c 24 50 49 8b 42 ?? 88 0c 07 83 fe 08 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_HR_2147849044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.HR!MTB"
        threat_id = "2147849044"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b 0c 00 33 8a 94 00 00 00 48 8b 82 c0 00 00 00 41 89 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MUR_2147849045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MUR!MTB"
        threat_id = "2147849045"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8b f2 49 8d 1c 02 4c 8b 94 24 ?? ?? ?? ?? 4d 2b d6 4c 89 94 24 ?? ?? ?? ?? 48 2b f8 41 8a 0c 1a 2a 8c 24 ?? ?? ?? ?? 32 8c 24 ?? ?? ?? ?? 49 8b 41 ?? 88 0c 03 83 fe 08 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MUL_2147849046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MUL!MTB"
        threat_id = "2147849046"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8d 0c 03 4d 2b f3 49 8b f3 4c 89 b4 24 ?? ?? ?? ?? 4c 2b c0 43 8a 0c 0e 2a 8c 24 ?? ?? ?? ?? 32 8c 24 ?? ?? ?? ?? 49 8b 42 48 41 88 0c 01 83 ff ?? 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_RH_2147849471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.RH!MTB"
        threat_id = "2147849471"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 0b ca 48 0f af c1 48 89 42 ?? 49 63 96 ?? ?? ?? ?? 49 8b 0e 49 8b 46 ?? 8a 14 0a 41 32 14 00 49 8b 46 ?? 41 88 14 00 49 ff c0 49 8b 86 ?? ?? ?? ?? 49 8b 8e ?? ?? ?? ?? 49 0b cb 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MIT_2147850183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MIT!MTB"
        threat_id = "2147850183"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 ff c6 85 c0 74 ?? 49 8b 8a 70 01 00 00 49 8b 82 ?? ?? ?? ?? 48 0d c8 1a 00 00 48 31 41 10 49 8b 4a 20 42 8a 04 09 02 c0 0a c2 42 88 04 09 eb 08 49 8b 42 20 41 88 14 01 49 81 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MIP_2147850267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MIP!MTB"
        threat_id = "2147850267"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 2b d8 49 8b 80 d0 03 00 00 49 8b 90 a8 02 00 00 48 8b 88 50 03 00 00 48 81 e9 49 1c 00 00 48 09 8a c8 03 00 00 49 8b 80 28 01 00 00 49 8b 90 e0 03 00 00 48 8b 88 c8 03 00 00 49 03 cf 48 31 8a f0 01 00 00 41 8a 0c 3c 2a 8c 24 98 00 00 00 32 8c 24 90 00 00 00 49 8b 40 50 88 0c 07 83 fe 08 0f 84 84 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MA_2147888643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MA!MTB"
        threat_id = "2147888643"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MZtmeI03" ascii //weight: 1
        $x_1_2 = "ZmwQhe0ef" ascii //weight: 1
        $x_1_3 = "NEsMF" ascii //weight: 1
        $x_1_4 = "vcsfile" ascii //weight: 1
        $x_1_5 = "QXZ6H" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_YAG_2147888772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.YAG!MTB"
        threat_id = "2147888772"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 8b d3 48 8b 8d ?? ?? ?? ?? 4c 8b 85 ?? ?? ?? ?? 41 69 80 ?? ?? ?? ?? ?? ?? ?? ?? 48 31 8d ?? ?? ?? ?? 44 03 d0 48 8d 41 01 48 89 85 ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 48 8b 88 ?? ?? ?? ?? 48 81 f1 ?? ?? ?? ?? 48 29 8d ?? ?? ?? ?? 41 8b ca 41 8a 80 ?? ?? ?? ?? d3 ea 34 42 48 63 8d ?? ?? ?? ?? 22 d0 48 8b 45 ?? 88 14 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_TRA_2147888914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.TRA!MTB"
        threat_id = "2147888914"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 2b c2 48 01 83 48 03 00 00 48 8b 83 ?? ?? ?? ?? 48 05 d8 28 00 00 48 01 81 58 02 00 00 48 63 93 c0 03 00 00 48 8b 43 30 48 8b 4b 08 8a 14 0a 41 32 14 00 48 8b 43 70 41 88 14 00 48 8b 93 78 02 00 00 81 ba 20 03 00 00 c8 2a 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_TRR_2147888915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.TRR!MTB"
        threat_id = "2147888915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b cf 44 89 54 24 30 89 44 24 28 8b 44 24 70 89 44 24 20 e8 b9 cd ff ff 8b 4f 28 41 83 c4 04 2b 8f f8 02 00 00 44 8b e8 48 8b 97 58 01 00 00 41 2b ce 44 8b 8c 24 ?? ?? ?? ?? 44 33 f9 44 8b 44 24 68 48 2b d3 44 8b 94 24 30 01 00 00 44 8b 9c 24 20 01 00 00 49 63 cc 48 3b ca 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_AA_2147888989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.AA!MTB"
        threat_id = "2147888989"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c2 41 8b d0 c1 ea 08 89 45 ?? 48 8b 85 ?? ?? ?? ?? 88 14 01 ff 85 ?? ?? ?? ?? 48 63 8d ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 44 88 04 01 ff 85 ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8d 42 ?? 31 85 ?? ?? ?? ?? 8b 45 ?? 2d ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 8b 45 ?? 09 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_AB_2147888990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.AB!MTB"
        threat_id = "2147888990"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 80 88 00 00 00 49 8b f8 49 8b 88 18 02 00 00 48 0f af c0 48 69 c0 ?? ?? 00 00 49 89 80 88 00 00 00 49 8b 80 b0 01 00 00 48 05 ?? ?? 00 00 48 09 81 98 01 00 00 49 8b c8 49 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_AB_2147888990_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.AB!MTB"
        threat_id = "2147888990"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 8a 0c 30 2a 8c 24 a8 00 00 00 32 8c 24 a0 00 00 00 49 8b 40 20 41 88 0c 06 83 fd 08 0f 84 ?? ?? 00 00 49 8b 50 20 8b cd b8 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 00 48 8b ce 48 81 c9 ?? ?? 00 00 48 0f af c1 49 89 00 49 8b 48 20 41 8a 04 0f 02 c0 [0-3] 41 88 04 0f e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_FS_2147889035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.FS!MTB"
        threat_id = "2147889035"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 8a 0c 17 2a 8c 24 88 00 00 00 32 8c 24 80 00 00 00 49 8b 43 20 41 88 0c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MB_2147889095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MB!MTB"
        threat_id = "2147889095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 0f af 48 6c 8b 48 1c 81 c1 ?? ?? ?? ?? 0f af ca 41 8b d1 45 8b c1 c1 ea 10 41 c1 e8 08 89 8e dc 00 00 00 48 8b 05 ?? ?? ?? ?? 48 63 48 70 48 8b 05 ?? ?? ?? ?? 88 14 01 48 8b 05 ?? ?? ?? ?? ff 40 70}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_FLI_2147889108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.FLI!MTB"
        threat_id = "2147889108"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c9 48 8b 54 24 40 0f b6 0c 0a 0f af c1 6b 0d 84 b1 11 00 03 48 63 c9 48 8b 54 24 48 0f b6 0c 0a 03 c1 0f b6 4c 24 03 33 c1 0f b6 0c 24 48 63 c9 48 8b 94 24 ?? ?? ?? ?? 89 04 8a 0f b6 04 24 fe c8 88 04 24 0f b6 44 24 01 0f b6 0c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_XEQ_2147889520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.XEQ!MTB"
        threat_id = "2147889520"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 31 0c 12 49 83 c2 04 8b 83 ec 00 00 00 ff c8 01 43 54 48 8b 0d 42 7f 05 00 8b 83 d0 00 00 00 01 81 80 00 00 00 b8 d1 92 19 00 2b 05 03 80 05 00 01 83 f8 00 00 00 48 8b 15 1e 7f 05 00 8b 8a e0 00 00 00 03 8a 90 00 00 00 8b 42 78 0f af c1 89 42 78 8b 05 67 7f 05 00 83 c0 ee 09 83 ec 00 00 00 49 81 fa 40 05 06 00 7c 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MOB_2147890106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MOB!MTB"
        threat_id = "2147890106"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 2d 18 27 00 00 48 01 83 48 03 00 00 48 8b 83 98 00 00 00 49 03 c2 48 01 81 58 02 00 00 48 8b 43 30 48 63 93 c0 03 00 00 48 8b 4b 08 8a 14 0a 42 32 14 00 48 8b 43 70 41 88 14 00 81 bb 50 03 00 00 62 27 00 00 75 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_CCAU_2147890134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.CCAU!MTB"
        threat_id = "2147890134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 43 58 8b 43 38 03 83 c4 00 00 00 33 05 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? b8 11 00 00 00 2b 83 e0 00 00 00 01 43 54 48 8b 0d ?? ?? ?? ?? 8b 43 04 29 41 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_WIP_2147890295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.WIP!MTB"
        threat_id = "2147890295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 ff c5 4c 8b 84 24 30 01 00 00 41 83 c4 02 44 0f b6 9c 24 20 01 00 00 41 83 c7 03 48 63 c8 48 63 05 ?? ?? ?? ?? 44 0f b7 cb 49 89 0c c6 8b c7 99 42 8d 0c 8d 00 00 00 00 f7 3d ?? ?? ?? ?? 0f b6 0c ce ff c7 32 c8 48 8b 44 24 78 00 0c 28 41 8d 49 24 ff 0d ?? ?? ?? ?? 48 63 ef 48 3b 2c ce 0f 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_WIW_2147890296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.WIW!MTB"
        threat_id = "2147890296"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 0f af c2 41 8b d0 c1 ea 10 89 83 c4 00 00 00 48 63 0d ?? ?? ?? ?? 48 8b 83 98 00 00 00 88 14 01 41 8b d0 ff 05 ?? ?? 04 00 8b 43 58 2b 43 50 05 b4 d7 5c 44 c1 ea 08 31 05 ?? ?? 04 00 8b 83 c4 00 00 00 2d 58 3f 1e 00 31 43 44 48 8b 0d ?? ?? 04 00 8b 43 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MC_2147890491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MC!MTB"
        threat_id = "2147890491"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 0f af 43 24 41 8b d0 c1 ea 10 88 14 01 41 8b d0 44 01 53 40 48 8b 05 ?? ?? ?? ?? c1 ea 08 8b 88 f4 00 00 00 41 33 ca 29 8b b4 00 00 00 8b 05 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 05 6e e7 e9 ff 09 05 ?? ?? ?? ?? 8b 41 34 2d ?? ?? ?? ?? 01 81 ?? ?? ?? ?? 48 63 4b 40 48 8b 43 78 88 14 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_REE_2147890514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.REE!MTB"
        threat_id = "2147890514"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b d1 48 8b 05 16 0a 05 00 c1 ea 08 ff 40 40 48 8b 43 78 48 63 0d 55 0a 05 00 88 14 01 b8 cd b3 09 00 ff 05 47 0a 05 00 2b 83 14 01 00 00 2b 83 90 00 00 00 01 83 fc 00 00 00 48 8b 43 78 48 63 0d 2a 0a 05 00 44 88 0c 01 ff 05 20 0a 05 00 48 8b 15 c9 09 05 00 8b 4a 34 33 8b d0 00 00 00 8b 82 f0 00 00 00 81 e9 5d 32 12 00 0f af c1 89 82 f0 00 00 00 b8 87 f3 02 00 2b 43 28 01 05 7d 0a 05 00 8b 83 90 00 00 00 33 c6 29 83 14 01 00 00 49 81 fb 80 29 00 00 7d 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_RED_2147891187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.RED!MTB"
        threat_id = "2147891187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 cf 0f af c1 49 63 c8 89 05 ?? ?? ?? ?? 48 8b 05 fb 2a 04 00 88 14 01 8b 0d ba 2a 04 00 8b 05 54 2b 04 00 03 cf 05 3a a5 f9 ff 89 0d a7 2a 04 00 31 05 ad 2a 04 00 48 8b 05 ?? ?? ?? ?? 48 63 c9 44 88 0c 01 8b 05 7d 2a 04 00 01 3d 87 2a 04 00 05 09 97 f6 ff 48 8b 15 ?? ?? ?? ?? 8b 8a fc 00 00 00 03 c8 8b 05 c1 2a 04 00 05 0c 92 f8 ff 89 0d 52 2a 04 00 01 82 94 00 00 00 8b 05 46 2a 04 00 48 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_JAR_2147891561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.JAR!MTB"
        threat_id = "2147891561"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af e8 b8 f6 1a 00 00 99 41 f7 7c cd 00 48 8b 8c 24 a0 00 00 00 41 03 92 bc 6a 00 00 44 0b da 44 89 1d 8a d4 10 00 49 63 c3 4c 8b 9c 24 a8 00 00 00 42 0f b6 04 20 0b c3 99 41 f7 f9 42 30 04 19 4c 63 0d 81 d4 10 00 44 0f b7 05 95 d4 10 00 88 1d 7a d4 10 00 45 8b d0 4a 8b 04 ce 48 2b 86 f0 d4 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_JC_2147891611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.JC!MTB"
        threat_id = "2147891611"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c1 89 43 ?? 8b 83 ?? ?? ?? ?? 05 ?? ?? ?? ?? 01 43 ?? 8b 8b ?? ?? ?? ?? 8d 41 ?? 31 43 ?? 8d 04 4d ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8b 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_YAH_2147891844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.YAH!MTB"
        threat_id = "2147891844"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f af c1 89 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 01 43 0c 8b 83 ?? ?? ?? ?? 83 e8 0c 31 43 70 48 8b 43 68 0f b6 4b 3c 41 0f b6 14 00 49 83 c0 04 48 8b 83 ?? ?? ?? ?? 0f af d1 48 63 4b 40 88 14 01 44 01 53 40 8b 43 70 41 2b c3 09 83}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_JD_2147892049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.JD!MTB"
        threat_id = "2147892049"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 0c 80 41 31 0c ?? 8b 8b ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 7d ?? 2b cf 83 c9 ?? 03 cf 48 8b 93 ?? ?? ?? ?? 48 63 83 ?? ?? ?? ?? 44 8b 04 82 85 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_JD_2147892049_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.JD!MTB"
        threat_id = "2147892049"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 04 01 ff 43 ?? 8b 83 ?? ?? ?? ?? 83 e8 ?? 09 83 ?? ?? ?? ?? 8b 43 ?? 2b 83 ?? ?? ?? ?? 33 43 ?? 35 ?? ?? ?? ?? 89 43 ?? 8b 43 ?? 03 c0 2b 43 ?? 2d ?? ?? ?? ?? 89 43 ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MD_2147893392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MD!MTB"
        threat_id = "2147893392"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 43 3c 0f af d0 48 8b 83 a0 00 00 00 88 14 01 44 8b 9b 98 00 00 00 ff 43 40 8b 83 f4 00 00 00 03 83 00 01 00 00 44 8b 83 bc 00 00 00 83 f0 01 01 83 e0 00 00 00 b8 ?? ?? ?? ?? 8b 93 e0 00 00 00 41 2b c0 03 93 08 01 00 00 01 43 28 83 f2 01 8b 73 40 44 0f af da 44 89 9b 98 00 00 00 49 81 fa ?? ?? ?? ?? 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_HC_2147894668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.HC!MTB"
        threat_id = "2147894668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 01 ff 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 8b 4b ?? 83 e9 ?? 0f af c1 89 83 ?? ?? ?? ?? 48 63 8b ?? ?? ?? ?? 48 8b 83 ?? ?? ?? ?? 44 88 04 01 ff 83 ?? ?? ?? ?? 8b 43 ?? 8b 8b ?? ?? ?? ?? 83 e9 ?? 0f af c1 89 43 ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_YAI_2147896160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.YAI!MTB"
        threat_id = "2147896160"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 74 03 41 d3 c8 49 63 82 4c 05 00 00 44 01 04 82 41 b8 ?? ?? ?? ?? 4d 8b 8a}  //weight: 1, accuracy: Low
        $x_1_2 = {41 8b 0c 80 41 31 0c 90 41 8b 8a 7c 05 00 00 81 e1 1f 00 00 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_NH_2147896744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.NH!MTB"
        threat_id = "2147896744"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 63 c5 48 98 32 14 30 48 8b 05 ?? ?? ?? ?? 0f b6 4c 06 ?? 0f b6 c2 33 d2 0f af c1 0f b6 cb 41 ?? ?? 02 c3 43 ?? ?? ?? 0f b6 07 48 ?? ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_NI_2147896745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.NI!MTB"
        threat_id = "2147896745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 33 c6 0f af 05 ?? ?? ?? ?? 3b f8 74 ?? 8b 8b ?? ?? ?? ?? 23 4b ?? 41 03 cc ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 35 ?? ?? ?? ?? 0f af c8 89 0d ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 41 83 c7 ?? 8b c2 2b 83 ?? ?? ?? ?? 0f af 81 ?? ?? ?? ?? 44 3b f8 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_NJ_2147896971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.NJ!MTB"
        threat_id = "2147896971"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0b cb 39 88 ?? ?? ?? ?? 76 ?? 41 8d 81 ?? ?? ?? ?? 41 31 80 ?? ?? ?? ?? 41 8d 89 ?? ?? ?? ?? 23 0d ?? ?? ?? ?? 41 8b 40 ?? 0f af c1 41 89 40 ?? 41 8d 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_NK_2147896972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.NK!MTB"
        threat_id = "2147896972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 44 8d ?? 32 04 cd ?? ?? ?? ?? 0f b6 c8 41 ?? ?? ?? ?? 0f af c1 41 ?? ?? ?? 8b 05 ?? ?? ?? ?? 0f b7 15 ?? ?? ?? ?? 83 c0 ?? 48 63 c8 41 ?? ?? ?? ?? 66 89 04 4b 8b 05 ?? ?? ?? ?? 44 3b c8 7c ?? 4c 8b 05 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_PACB_2147899056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.PACB!MTB"
        threat_id = "2147899056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 42 58 05 61 34 13 00 31 81 ac 00 00 00 48 8b 05 ?? ?? ?? ?? 8b 88 fc 00 00 00 8b c2 41 31 8a b0 00 00 00 48 8b 0d ?? ?? ?? ?? 0f af c2 01 05 ?? ?? ?? ?? ff c2 3b 51 54 76 c4}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f8 48 8b 05 ?? ?? ?? ?? 8b 48 4c 8b 45 f0 33 0d ?? ?? ?? ?? 0f af d1 0f af c2 89 45 f8 48 8b 05 ?? ?? ?? ?? 8b 88 e0 00 00 00 33 0d ?? ?? ?? ?? 0b 88 f0 00 00 00 09 0d ?? ?? ?? ?? 44 03 c3 8b 4d 20 8b 45 ec 23 c8 44 3b c1 75 b2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_AMCC_2147901981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.AMCC!MTB"
        threat_id = "2147901981"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 60 8b 44 24 40 35 ?? ?? ?? ?? 89 44 24 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_TNK_2147902486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.TNK!MTB"
        threat_id = "2147902486"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 41 01 88 78 01 00 00 8b 05 ?? ?? ?? ?? 41 2b 80 80 01 00 00 48 8b 0d da 04 0a 00 05 5d ee 1a 00 31 81 dc 00 00 00 48 8b 0d c8 04 0a 00 41 8b 80 34 01 00 00 01 81 ?? ?? ?? ?? 41 8b 80 88 00 00 00 48 8b 0d ad 04 0a 00 2d 6e d6 07 00 09 41 18 49 81 fa 08 8c 0d 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_AMMF_2147907583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.AMMF!MTB"
        threat_id = "2147907583"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 81 33 c2 48 63 4c 24 ?? 48 8b 94 24 ?? ?? ?? ?? 48 8b 92 ?? ?? ?? ?? 89 04 8a 48 8b 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_DDD_2147909856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.DDD!MTB"
        threat_id = "2147909856"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 c1 ea 08 48 8b 05 35 6d 0c 00 89 0d f3 6d 0c 00 8b 88 c4 00 00 00 33 0d 53 6d 0c 00 81 e9 fe e3 15 00 09 0d eb 6d 0c 00 49 63 4f 6c 49 8b 87 ?? ?? ?? ?? 88 14 01 41 ff 47 6c 41 8b 87 ac 00 00 00 8b 0d d4 6d 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_YAJ_2147910569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.YAJ!MTB"
        threat_id = "2147910569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 83 ac 00 00 00 48 8b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 41 8b d0 2b 48 6c 81 e9 ?? ?? ?? ?? c1 ea 08 31 8b 40 01 00 00 48 8b 05 da 55 11 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_AAX_2147910675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.AAX!MTB"
        threat_id = "2147910675"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c2 33 d2 48 c1 e8 0c 49 f7 34 c8 49 89 04 c8 48 b8 97 57 e9 56 a3 89 25 ad 4d 31 34 d9 0f b6 0d 7a ab 16 00 4c 8b 05 ?? ?? ?? ?? 49 0b d8 48 f7 e3 48 c1 ea 09 41 32 d7 41 ff c7 0f b6 c2 0f af c8 88 0d 57 ab 16 00 45 3b fc 0f 8f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_YAK_2147911065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.YAK!MTB"
        threat_id = "2147911065"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 cf 8b 7d ff 4d 89 f4 4d 89 fa 48 33 45 ee bf ?? ?? ?? ?? 4c 89 2d f9 92 13 00 8b 3d e2 96 13 00 8b 55 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_BKZ_2147923239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.BKZ!MTB"
        threat_id = "2147923239"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 0f b6 09 41 0f b6 44 09 ?? 00 41 01 44 0f b6 41 01 41 0f b6 54 09 02 41 0f b6 44 08 02 41 88 44 09 ?? 41 88 54 08 ?? 0f b6 01 0f b6 51 01 0f b6 54 0a 02 02 54 08 ?? 0f b6 c2 0f b6 54 08 02 43 32 54 13 ff 41 88 52 ff 48 83 eb 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MZV_2147926755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MZV!MTB"
        threat_id = "2147926755"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {22 c8 48 8b 44 24 78 41 30 0c 00 43 8d 04 1b 48 63 c8 48 8b 05 ?? ?? ?? ?? 8a 14 48 02 16 48 8d 76 08 48 8b 05 ?? ?? ?? ?? 02 54 24 60 42 32 14 28 4d 8d 6d ?? 41 30 17 4d 03 f9 48 8b 04 24 0f b7 80 ?? ?? ?? ?? 44 3b d0 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_FFZ_2147928978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.FFZ!MTB"
        threat_id = "2147928978"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 89 ca 41 83 f2 ff 41 89 c3 45 21 d3 83 f0 ff 21 c1 41 09 cb 44 88 da 41 88 14 30 31 c0 8b 4c 24 ?? 83 e8 01 29 c1 89 4c 24 08 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_GA_2147932797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.GA!MTB"
        threat_id = "2147932797"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 8b 0c 30 33 4a 60 48 8b 83 80 00 00 00 41 89 0c 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_GB_2147933113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.GB!MTB"
        threat_id = "2147933113"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b 83 20 01 00 00 2b 41 20 05 d1 56 07 00 31 81 8c 00 00 00 49 81 fa d0 86 09 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_TYP_2147933204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.TYP!MTB"
        threat_id = "2147933204"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 29 d0 29 c1 88 ca 0f b6 c2 41 89 c0 43 0f b6 44 01 ?? 4c 8b 44 24 18 4c 63 5c 24 ?? 43 0f b6 0c 18 41 89 ca 41 83 f2 ff 89 c6 44 21 d6 83 f0 ff 21 c1 09 ce 40 88 f2 43 88 14 18 31 c0 8b 4c 24 08 83 e8 01 29 c1 89 4c 24 08 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_ZMN_2147936479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.ZMN!MTB"
        threat_id = "2147936479"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {41 ff c0 49 2b 86 38 01 00 00 49 01 82 40 03 00 00 49 8b 4e 38 48 8b 81 ?? ?? ?? ?? 49 09 86 f8 00 00 00 48 ff 81 ?? ?? ?? ?? 49 63 96 00 04 00 00 49 8b 4e 10 49 8b 46 40 8a 14 0a 42 32 14 08 49 8b 46 50 41 88 14 01 33 d2 49 63 8e 00 04 00 00}  //weight: 4, accuracy: Low
        $x_1_2 = "sXtvnXjHyP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_TOU_2147937227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.TOU!MTB"
        threat_id = "2147937227"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 83 e7 69 49 81 c6 34 a8 45 41 48 83 c6 55 49 83 f5 99 48 81 6c 24 40 01 00 00 00 0f 85 de ff ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_VZB_2147939873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.VZB!MTB"
        threat_id = "2147939873"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4d 63 c1 41 f7 fa 41 ff c2 34 27 0f b6 c8 43 0f b6 04 30 0f af c1 43 88 04 30 8b 15 cc 6b 18 00 8d 04 12 81 f2 29 0c 00 00 48 63 c8 48 8b 05 7d 6b 18 00 21 14 88 0f b6 0d ?? ?? ?? ?? 48 8b 05 64 6b 18 00 44 3b 14 88 7d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_MPG_2147941905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.MPG!MTB"
        threat_id = "2147941905"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 f7 f9 88 84 24 11 18 00 00 48 8d 05 aa cf 0b 00 48 89 84 24 e0 9b 02 00 0f be 05 53 43 02 00 48 8b 8c 24 80 60 01 00 0f be 09 d3 f8 48 8b 8c 24 c0 27 02 00 88 01 48 8b 84 24 ?? ?? ?? ?? 0f bf 00 89 84 24 a0 a0 01 00 81 bc 24 a0 a0 01 00 c2 3c 00 00 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_PPG_2147942009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.PPG!MTB"
        threat_id = "2147942009"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f be 09 0b c1 88 84 24 08 b9 00 00 c7 84 24 ?? ?? ?? ?? 99 00 f1 aa 8b 84 24 9c a7 00 00 8b 8c 24 9c 9c 00 00 2b c8 8b c1 89 84 24 ?? b4 01 00 8b 84 24 c8 58 01 00 99 48 8b 8c 24 88 30 01 00 f7 39 8b 8c 24 ?? b4 01 00 3b c8 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_AZL_2147942279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.AZL!MTB"
        threat_id = "2147942279"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 00 0f b6 8c 24 69 9a 01 00 2b c1 48 8b 8c 24 f0 01 00 00 88 01 e8 ?? ?? ?? ?? 48 8b 80 f8 0f 00 00 48 8b 8c 24 98 ca 00 00 48 89 4c 24 20 45 33 c9 45 33 c0 ba 02 00 00 00 48 8b 8c 24 ?? 60 01 00 ff 50 48}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_AHB_2147945649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.AHB!MTB"
        threat_id = "2147945649"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 45 a4 66 c7 45 a0 02 00 b9 50 00 00 00 48 8b ?? ?? ?? ?? 00 ff d0 66 89 45 a2 48 8d 55 a0 48 8b 85 58 01 00 00 41 b8 10 00 00 00 48 89 c1 48 8b ?? ?? ?? ?? 00 ff d0}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_GTB_2147948840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.GTB!MTB"
        threat_id = "2147948840"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c8 8b c1 89 84 24 ?? ?? ?? ?? 0f be 44 24 ?? 83 f0 7d 88 44 24 ?? 0f b6 44 24}  //weight: 10, accuracy: Low
        $x_1_2 = "deadlily Aselline" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bumblebee_GTB_2147948840_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bumblebee.GTB!MTB"
        threat_id = "2147948840"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "I_I^I]I\\I[IZIYIXH_H^H]H[HZHYHXHPHQHRHSHUHVHWIPIQIRISITIUIVIW" ascii //weight: 10
        $x_1_2 = "HZHYHXHPHQHRHSHUHVHWIPIQIRISITIUIVI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

