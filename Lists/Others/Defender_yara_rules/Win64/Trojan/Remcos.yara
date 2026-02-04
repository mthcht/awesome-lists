rule Trojan_Win64_Remcos_NR_2147901858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remcos.NR!MTB"
        threat_id = "2147901858"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to execute the .bat file" ascii //weight: 1
        $x_1_2 = "cmd/Cstart/B" ascii //weight: 1
        $x_1_3 = "Failed to download the filesrc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remcos_RP_2147919949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remcos.RP!MTB"
        threat_id = "2147919949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "205"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Kronus.exe" ascii //weight: 100
        $x_100_2 = "Kronus.dll" ascii //weight: 100
        $x_1_3 = "ctx---- [ hijack ]" ascii //weight: 1
        $x_1_4 = "[ KeepUnwinding ]" ascii //weight: 1
        $x_1_5 = "bcrypt.dll" ascii //weight: 1
        $x_1_6 = "PROCESSOR_COUNT" ascii //weight: 1
        $x_1_7 = "anonymous namespace'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remcos_AREM_2147930781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remcos.AREM!MTB"
        threat_id = "2147930781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 ff c1 45 89 dd 31 d3 41 0f b6 d3 41 c1 ed 18 8b 94 ?? ?? ?? ?? ?? 42 33 14 a8 44 0f b6 eb 42 33 94 a8 ?? ?? ?? ?? 41 89 dd 41 c1 ed 18 42 33 94 a8 ?? ?? ?? ?? 41 89 d6 44 89 da 41 c1 eb 10 0f b6 d6 45 0f b6 db 41 89 d5 42 8b 94 a8 ?? ?? ?? ?? 44 31 f2 42 33 94 98 ?? ?? ?? ?? 41 89 d7 0f b6 d7 c1 eb 10 41 89 d3 0f b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remcos_GVA_2147935571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remcos.GVA!MTB"
        threat_id = "2147935571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 01 d0 44 89 c2 31 ca 88 10 48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 00 0f b6 d0}  //weight: 3, accuracy: High
        $x_2_2 = {48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remcos_GVB_2147935572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remcos.GVB!MTB"
        threat_id = "2147935572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 01 d0 89 ca 88 10 48 8b 55 10 48 8b 45 f8 48 01 d0 44 0f b6 00}  //weight: 3, accuracy: High
        $x_2_2 = {0f b6 0c 02 48 8b 55 10 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remcos_NQA_2147956409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remcos.NQA!MTB"
        threat_id = "2147956409"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 33 4c d8 10 4c 89 09 4c 8b 0a 49 c1 c1 03 4c 33 09}  //weight: 1, accuracy: High
        $x_2_2 = "*!*%*)*-*1*5*9*=*A*E*I*M*Q*U*Y*]*a*e*i*m*q*u*y*" ascii //weight: 2
        $x_1_3 = "OpenRemoteBaseKey" ascii //weight: 1
        $x_1_4 = "DependencyInjection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remcos_GTD_2147958503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remcos.GTD!MTB"
        threat_id = "2147958503"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 8b 7c 24 ?? 4c 8b 6c 24 ?? 41 8d 47 ?? 89 44 24 ?? 45 3b 7d ?? 73 ?? 41 8b c7 41 0f b6 44 05 ?? 33 c7 44 0f b6 e0 41 3b 76 ?? 73 ?? 8b c6 45 88 64 06 ?? ff c6 3b ee}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remcos_ARO_2147962394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remcos.ARO!MTB"
        threat_id = "2147962394"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 85 74 0a 00 00 4d c6 85 75 0a 00 00 dc c6 85 76 0a 00 00 00 c6 85 77 0a 00 00 b0 c6 85 78 0a 00 00 15 c6 85 79 0a 00 00 ce c6 85 7a 0a 00 00 4e c6 85 7b 0a 00 00 0a c6 85 7c 0a 00 00 c9 c6 85 7d 0a 00 00 c6 c6 85 7e 0a 00 00 d4 c6 85 7f 0a 00 00 25 c6 85 80 0a 00 00 14 c6 85 81 0a 00 00 27 c6 85 82 0a 00 00 ab c6 85 83 0a 00 00 55 c6 85 84 0a 00 00 67 c6 85 85 0a 00 00 3c c6 85 86 0a 00 00 80 c6 85 87 0a 00 00 76 c6 85 88 0a 00 00 c1 c6 85 89 0a 00 00 6f c6 85 8a 0a 00 00 37 c6 85 8b 0a 00 00 e8 c6 85 8c 0a 00 00 bb}  //weight: 2, accuracy: High
        $x_1_2 = {c6 85 66 0a 00 00 4d c6 85 67 0a 00 00 01 c6 85 68 0a 00 00 d9 c6 85 69 0a 00 00 cc c6 85 6a 0a 00 00 ee c6 85 6b 0a 00 00 cc c6 85 6c 0a 00 00 96 c6 85 6d 0a 00 00 42 c6 85 6e 0a 00 00 a0 c6 85 6f 0a 00 00 23 c6 85 70 0a 00 00 68 c6 85 71 0a 00 00 ae c6 85 72 0a 00 00 b8 c6 85 73 0a 00 00 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

