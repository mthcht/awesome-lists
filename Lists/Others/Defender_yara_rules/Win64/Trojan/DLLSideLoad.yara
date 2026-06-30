rule Trojan_Win64_DLLSideLoad_MKE_2147968180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.MKE!MTB"
        threat_id = "2147968180"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Assets\\x86\\Data\\vcredist_x64.dll" ascii //weight: 3
        $x_2_2 = "\\Assets\\x86\\Data\\vcredist_x86.dll" ascii //weight: 2
        $x_2_3 = "Execute" ascii //weight: 2
        $x_1_4 = "msiexec.exe" ascii //weight: 1
        $x_1_5 = "CreateProcess" ascii //weight: 1
        $x_1_6 = "autorun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_MKR_2147968420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.MKR!MTB"
        threat_id = "2147968420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 31 34 5a 0f b6 c0 66 89 04 4a 41 3b 4c 24 10 7c}  //weight: 5, accuracy: High
        $x_1_2 = "autorun.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_AYWB_2147971935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.AYWB!MTB"
        threat_id = "2147971935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 44 24 44 32 04 1e 88 44 24 44 48 ff c3 48 81 fb 94 a6 04 00 72}  //weight: 5, accuracy: High
        $x_2_2 = {4c 8b cb 49 c1 e9 0c 49 8b c6 49 f7 e1 48 c1 ea 03 48 8d 04 d2 4c 2b c8 44 8b c7 0f b6 14 1e 0f b6 cb e8 29 f4 ff ff 88 04 1e 48 ff c3 48 81 fb 94 a6 04 00 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_GVB_2147971943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.GVB!MTB"
        threat_id = "2147971943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 c1 e1 0d 33 c8 8b d1 c1 ea 11 32 d1 0f b6 c2 c0 e0 05 43 32 04 08 32 c2 43 88 04 08 49 ff c0 49 81 f8 5c 05 00 00 72 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_GVB_2147971943_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.GVB!MTB"
        threat_id = "2147971943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 0c 24 8b 04 24 8b 4c 24 08 31 c1 81 e1 fb a9 00 00 29 4c 24 04 83 44 24 0c 36 8b 44 24 04}  //weight: 1, accuracy: High
        $x_1_2 = {30 c1 80 f1 a6 88 0c 04 40 83 f8 13 0f b6 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_SS_2147971956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.SS!MTB"
        threat_id = "2147971956"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8d ec ca ff ff 81 f1 2e 13 00 00 8b 95 [0-4] 33 d1 89 95 [0-4] c6 85 6c d4 ff ff c9 c6 85 6d d4 ff ff 4d c6 85 6e d4 ff ff 91 c6 85 6f d4 ff ff b2 c6 85 70 d4 ff ff f8 c6 85 71 d4 ff ff a8 c6 85 72 d4 ff ff 53}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 8d 00 f3 ff ff 33 c8 89 8d 00 f3 ff ff 8b 95 00 f3 ff ff 83 e2 01 89 95 00 f3 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_C_2147971993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.C!MTB"
        threat_id = "2147971993"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {46 0f b6 14 00 45 31 ca 41 31 c2 45 88 14 00 48 ff c0 48 39 c2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_CA_2147971994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.CA!MTB"
        threat_id = "2147971994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 0f b6 04 30 41 31 f8 41 31 c0 44 88 04 06 48 ff c0 48 39 c2 7f e9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_GVC_2147972084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.GVC!MTB"
        threat_id = "2147972084"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 c8 11 da 89 85 78 ff ff ff 89 95 7c ff ff ff 8b 45 80 89 45 f4 c7 45 f0 00 00 00 00 eb 08 83 45 f4 01 83 45 f0 01 8b 45 f0 99 8b 8d 78 ff ff ff 8b 9d 7c ff ff ff f7 d9 83 d3 00 f7 db 39 c8 89 d0 19 d8 7c d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_GVD_2147972190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.GVD!MTB"
        threat_id = "2147972190"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c9 4c 39 e9 73 14 48 89 c8 31 d2 49 f7 f4 8a 44 15 00 30 04 0e 48 ff c1 eb e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_GVE_2147972208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.GVE!MTB"
        threat_id = "2147972208"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 07 84 c0 74 43 8b 4e 10 34 5a 0f b6 d0 3b 4e 14 73 1d 83 7e 14 08 8d 41 01 89 46 10 8b c6 72 02 8b 06 66 89 14 48 33 d2 66 89 54 48 02 eb 10}  //weight: 1, accuracy: High
        $x_1_2 = "powershell -Command Add-MpPreference -ExclusionPath" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_MCX_2147972490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.MCX!MTB"
        threat_id = "2147972490"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a0 3a 62 01 9e 48 02 00 60 59 87 01 1c 02 00 00 00 80 92 01 bc 99 3b 00 00 20 79 01 0c cd 0b 00 00 08 93 01 68 52 00 00 00 90 92 01 88 91 02 00 40 2e 3f 01 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 6e 3f}  //weight: 1, accuracy: High
        $x_1_2 = {cc cc cc cc cc e9 16 ce c0 00 e9 81 47 ba 00 e9 8c 49 87 00 e9 07 52 7f 00 e9 b2 7a 6f 00 e9 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

