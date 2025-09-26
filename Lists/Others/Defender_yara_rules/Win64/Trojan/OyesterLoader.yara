rule Trojan_Win64_OyesterLoader_OSH_2147922580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OyesterLoader.OSH!MTB"
        threat_id = "2147922580"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OyesterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 59 10 48 8b d3 48 8b 4a 60 45 8b ce 48 8b c1 66 44 39 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OyesterLoader_C_2147949039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OyesterLoader.C!MTB"
        threat_id = "2147949039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OyesterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 48 83 ec 20 48 8b 35 ?? ?? ?? ?? 48 8b 0e 48 8d ?? ?? ?? ?? 00 ba 01 00 00 00 45 31 c0 ff d0 b8 ?? ?? ?? ?? 48 03 06 48 83 c4 20 5e 48 ff e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OyesterLoader_CB_2147949142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OyesterLoader.CB!MTB"
        threat_id = "2147949142"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OyesterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 03 01 ff d0 31 c0}  //weight: 3, accuracy: High
        $x_2_2 = {4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 45 78 69 74 50 72 6f 63 65 73 73 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73}  //weight: 2, accuracy: High
        $x_1_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 00 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OyesterLoader_CC_2147949169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OyesterLoader.CC!MTB"
        threat_id = "2147949169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OyesterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {45 33 c0 41 8b d5 48 8d 81 ?? ?? ?? ?? ff d0}  //weight: 3, accuracy: Low
        $x_2_2 = {b8 4d 5a 00 00 66 39 07}  //weight: 2, accuracy: High
        $x_1_3 = "KERNEL32.DLL" ascii //weight: 1
        $x_1_4 = "LoadLibraryA" ascii //weight: 1
        $x_1_5 = "GetProcAddress" ascii //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OyesterLoader_Z_2147953278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OyesterLoader.Z!MTB"
        threat_id = "2147953278"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OyesterLoader"
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

