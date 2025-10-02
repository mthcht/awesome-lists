rule Trojan_Win64_Oyester_Z_2147953827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyester.Z!MTB"
        threat_id = "2147953827"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyester"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 44 89 f8 41 ff c7 44 88}  //weight: 1, accuracy: High
        $x_1_2 = {48 b8 0f b6 07 41 c1 e2 08 ff}  //weight: 1, accuracy: High
        $x_1_3 = {49 bf 0f b6 07 41 c1 e2 08 41}  //weight: 1, accuracy: High
        $x_1_4 = {48 b8 89 d0 66 c1 e8 05 8d 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyester_ZA_2147953828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyester.ZA!MTB"
        threat_id = "2147953828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyester"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8d 4c 24 48 c7 44 24 28 40 00 00 00 45 33 c0 48 c7 44 24 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyester_ZB_2147953829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyester.ZB!MTB"
        threat_id = "2147953829"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyester"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 53 50 48 85 d2 74 30 66 83 7b 48 00 76 29 41 b8 40 00 00 00 48 8d 4c 24 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyester_ZC_2147953830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyester.ZC!MTB"
        threat_id = "2147953830"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyester"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 89 44 5c 42 0f b6 01 84 c0 74 15 66 89 44 5c 44 48 83 c1 03 48 83 c3 03 48 83 fb 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyester_ZD_2147953831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyester.ZD!MTB"
        threat_id = "2147953831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyester"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 44 24 50 45 33 c9 89 44 24 48 45 33 c0 89 44 24 40 33 d2 89 44 24 38 33 c9 89 44 24 30 48 89 44 24 28 89 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyester_ZF_2147953832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyester.ZF!MTB"
        threat_id = "2147953832"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyester"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 41 39 ff 73 13 48 8b 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyester_ZE_2147953833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyester.ZE!MTB"
        threat_id = "2147953833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyester"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 48 8d 34 68 77 1a}  //weight: 1, accuracy: High
        $x_1_2 = "DllRegisterServer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

