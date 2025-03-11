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

