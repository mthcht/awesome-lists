rule Trojan_Win64_Zenpak_GXM_2147918428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenpak.GXM!MTB"
        threat_id = "2147918428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 f7 e1 48 c1 ea ?? 48 69 d2 ?? ?? ?? ?? 48 2b ca 42 8a 04 11 41 30 01 49 ff c1 41 81 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zenpak_GPA_2147919648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenpak.GPA!MTB"
        threat_id = "2147919648"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CimKKgoqi##" ascii //weight: 1
        $x_1_2 = "sKK4osCiy##" ascii //weight: 1
        $x_1_3 = "#KKMwozijQKNIo1CjW##" ascii //weight: 1
        $x_1_4 = "RYpGikcKR4pIC##" ascii //weight: 1
        $x_3_5 = "SwpLikwKTIpNCk4KTopPCk##" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zenpak_GPB_2147919649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenpak.GPB!MTB"
        threat_id = "2147919649"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 88 c2 02 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zenpak_GPC_2147920375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenpak.GPC!MTB"
        threat_id = "2147920375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 89 e5 56 8a 45 0c 8a 4d 08 88 c2 02 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zenpak_PAGE_2147929634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenpak.PAGE!MTB"
        threat_id = "2147929634"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f9 03 75 05 8b ce 48 8b d6}  //weight: 2, accuracy: High
        $x_2_2 = {41 30 00 ff c1 48 ff c2 49 ff c0 49 ff c9 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

