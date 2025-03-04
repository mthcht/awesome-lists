rule Trojan_Win64_Qakbot_ER_2147818028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.ER!MTB"
        threat_id = "2147818028"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kouOH.dll" ascii //weight: 1
        $x_1_2 = "AGUkfZ7fK5" ascii //weight: 1
        $x_1_3 = "BQ2ylpPvBO" ascii //weight: 1
        $x_1_4 = "CUmT6MBiTr" ascii //weight: 1
        $x_1_5 = "DBqNO3hRXq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_MP_2147819230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.MP!MTB"
        threat_id = "2147819230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 9c c7 45 a4 00 10 00 00 6a 40 8b 45 a4 50 8b 45 a0 03 45 c0 50 6a 00 ff 55 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_PC_2147832815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.PC!MTB"
        threat_id = "2147832815"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 0c 24 48 8b 54 24 30 eb 1e 0f b6 04 01 8b 4c 24 04 eb 00 33 c8 8b c1 eb e5 8b 44 24 38 39 04 24 73 0a e9 14 ff ff ff 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_PQ_2147842835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.PQ!MTB"
        threat_id = "2147842835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b 04 01 49 83 c1 04 8b 43 ?? 44 0f af 43 ?? 83 e8 ?? 09 43 ?? 8b 93 [0-4] 8b 4b ?? 8d 82 [0-4] 03 c1 31 43 ?? 8d 41 [0-4] 0b c2 89 83 [0-4] 48 63 8b [0-4] 48 8b 83 [0-4] 44 88 04 01 ff 83 [0-4] 8b 4b ?? 33 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_SJN_2147843090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.SJN!MTB"
        threat_id = "2147843090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c1 38 5c 0d ?? 75 ?? b8 ?? ?? ?? ?? 3b c8 0f 47 c8 85 c9 74 ?? 48 ?? ?? ?? 8d 43 ?? ff c3 88 02 48 ?? ?? 3b d9 72}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b c0 44 8b ce 33 d2 41 8b c6 41 f7 f4 42 8a 0c 2a 43 32 0c 3e 41 ff c6 41 88 08 49 ff c0 49 83 e9 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_MA_2147846894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.MA!MTB"
        threat_id = "2147846894"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dllmain64.dll" ascii //weight: 2
        $x_2_2 = "curl http://109.172.45.9/Leq/" ascii //weight: 2
        $x_2_3 = {41 b9 10 00 00 00 4c 8d 05 de 1f 00 00 48 8d 15 dd 1f 00 00 31 c9 ff 15 5b 60 00 00 31 d2 48 8d 0d e6 1f 00 00 48 8b 1d 3b 60 00 00 ff d3 b9 98 3a 00 00 ff 15 26 60 00 00 48 8d 0d 0b 20 00 00 ba 01 00 00 00 ff d3 31 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_LL_2147891820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.LL!MTB"
        threat_id = "2147891820"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 56 57 8b 40 0c 8b 78 14 85 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_EL_2147898822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.EL!MTB"
        threat_id = "2147898822"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 01 10 8b 8c 24 98 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {33 c8 8b c1}  //weight: 1, accuracy: High
        $x_1_3 = {48 63 4c 24 4c 48 8b 54 24 78}  //weight: 1, accuracy: High
        $x_1_4 = {88 04 0a e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_YY_2147898833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.YY!MTB"
        threat_id = "2147898833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {49 8b ca 83 e1 ?? 49 ff c2 8a 8c 01 ?? ?? ?? ?? 43 32 0c 01 41 88 08 49 ff c0 49 83 eb ?? 48 8b 05}  //weight: 100, accuracy: Low
        $x_100_3 = {48 8b cb 48 f7 e3 48 8b c3 48 ff c3 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 ?? 48 2b c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 43 32 04 08 41 88 01 49 ff c1 48 83 ee 01 48 b8}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_ST_2147898928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.ST"
        threat_id = "2147898928"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chickenfried" ascii //weight: 1
        $x_1_2 = "electricmadness" ascii //weight: 1
        $x_1_3 = "business.doc" ascii //weight: 1
        $x_1_4 = {3a 2f 2f 00 50 4f 53 54}  //weight: 1, accuracy: High
        $x_1_5 = {00 68 76 73 69 00}  //weight: 1, accuracy: High
        $x_1_6 = {65 6e 64 6c 65 73 73 00 61 70 70 65 61 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_Qakbot_AM_2147899158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.AM!MTB"
        threat_id = "2147899158"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 0f b6 04 08 48 63 84 24 ?? ?? ?? ?? 33 d2 b9 ?? ?? ?? ?? 48 f7 f1 0f b6 44 14 ?? 41 8b d0 33 d0 8b 4c 24 ?? 0f af 8c 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 2b c1 8b 4c 24 ?? 0f af 8c 24 ?? ?? ?? ?? 03 c1 2b 44 24 ?? 03 44 24 ?? 48 63 c8 48 8b 84 24 ?? ?? ?? ?? 88 14 08 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_A_2147900551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.A"
        threat_id = "2147900551"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 32 44 25 00 ff c5 41 88 00 49 ff c0 49 83 e9 01}  //weight: 1, accuracy: High
        $x_1_2 = {8b d3 48 89 [0-4] 45 33 c9 48 8d 0d [0-8] 4c 8b c0 48 8b f8 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_PAM_2147901660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.PAM!MTB"
        threat_id = "2147901660"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 29 c2 8b 85 ?? ?? 00 00 48 98 48 29 c2 48 89 d0 0f b6 84 05 ?? ?? 00 00 44 31 c8 41 88 00 48 83 85 ?? ?? 00 00 01 48 8b 85 ?? ?? 00 00 48 39 85 ?? ?? 00 00 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_PAN_2147901985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.PAN!MTB"
        threat_id = "2147901985"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "business.doc" ascii //weight: 1
        $x_1_2 = {3a 2f 2f 00 50 4f 53 54}  //weight: 1, accuracy: High
        $x_1_3 = {65 6e 64 6c 65 73 73 00 61 70 70 65 61 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_SA_2147902108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.SA!MTB"
        threat_id = "2147902108"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 8b 4c 24 ?? eb ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b c0 48 ?? ?? ?? ?? eb ?? 33 c8 8b c1 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {ff c0 89 04 24 e9 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 04 24 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Qakbot_YAT_2147925074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Qakbot.YAT!MTB"
        threat_id = "2147925074"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 75 72 6c 20 68 74 74 70 3a 2f 2f 31 33 35 2e 31 32 35 2e 31 37 37 2e 39 34 2f [0-9] 2e 64 61 74 20 2d 6f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

