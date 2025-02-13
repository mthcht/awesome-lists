rule Trojan_Win64_Bazzarldr_GS_2147765510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazzarldr.GS!MTB"
        threat_id = "2147765510"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazzarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d0 c7 44 [0-2] 00 00 00 00 c7 44 [0-2] 40 00 00 00 41 b9 00 10 00 00 49 [0-2] ba 00 00 00 00 48 [0-2] ff d3 48 89 [0-2] 8b 45 [0-2] 89 c1 48 8b [0-2] 48 8b [0-2] 49 89 [0-2] 48 89 [0-2] e8 [0-4] 8b 55 [0-2] 48 8b [0-2] 89 54 [0-2] 48 8d [0-2] 48 89 [0-4] 48 8b [0-2] 48 89 [0-4] 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 00 48 89 c1 48 8b 05 [0-4] ff d0 85 c0 0f 94 c0 84 c0 74}  //weight: 10, accuracy: Low
        $x_10_2 = {75 07 b8 00 00 00 00 eb 17 48 8b [0-2] 48 89 [0-2] 48 8b [0-2] ff d0}  //weight: 10, accuracy: Low
        $x_1_3 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_4 = "CryptEncrypt" ascii //weight: 1
        $x_1_5 = "memcpy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazzarldr_GT_2147765511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazzarldr.GT!MTB"
        threat_id = "2147765511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazzarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {10 00 00 31 d2 c7 44 [0-2] 00 00 00 00 c7 44 [0-2] 40 00 00 00 48 [0-2] 49 [0-2] ff d3 44 8b [0-6] 48 [0-2] 48 [0-2] 48 [0-2] e8 [0-4] 8b 84 [0-5] 48 89 [0-3] 45 31 [0-2] 31 d2 41 b8 01 00 00 00 48 8b [0-3] 89 44 [0-2] 48 8d [0-6] 48 89 [0-3] ff 15 [0-4] 85 c0 b8 00 00 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_3 = "CryptEncrypt" ascii //weight: 1
        $x_1_4 = "memcpy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazzarldr_GU_2147765516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazzarldr.GU!MTB"
        threat_id = "2147765516"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazzarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Stupid Defender" ascii //weight: 10
        $x_1_2 = "LdrLoadDll" ascii //weight: 1
        $x_1_3 = "GetCurrentProcess" ascii //weight: 1
        $x_1_4 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_5 = "CryptEncrypt" ascii //weight: 1
        $x_1_6 = "memcpy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazzarldr_GV_2147765668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazzarldr.GV!MTB"
        threat_id = "2147765668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazzarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {10 00 00 49 [0-2] ba 00 00 00 00 48 [0-2] ff d3 48 [0-4] 8b [0-2] 89 [0-2] 48 8b [0-2] 49 89 [0-2] 48 8b [0-2] 48 89 [0-2] e8 [0-4] 8b [0-2] 48 8b [0-2] 89 54 [0-2] 48 8d [0-2] 48 89 [0-4] 48 8b [0-2] 48 89 [0-4] 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 00 48 89 [0-2] 48 8b [0-6] ff d0}  //weight: 5, accuracy: Low
        $x_1_2 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_3 = "CryptEncrypt" ascii //weight: 1
        $x_1_4 = "memcpy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazzarldr_GW_2147765669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazzarldr.GW!MTB"
        threat_id = "2147765669"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazzarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 f6 48 89 [0-2] 31 d2 49 89 [0-2] 41 b9 00 10 00 00 ff 15 [0-4] 48 89 [0-2] 48 89 [0-2] 4c 89 [0-2] 49 89 [0-2] e8 [0-4] 8b 45 00 48 [0-4] [0-4] 89 44 [0-2] 48 [0-4] 48 [0-4] 31 d2 41 b8 01 00 00 00 45 31 [0-2] ff 15 [0-4] 85 c0 0f}  //weight: 5, accuracy: Low
        $x_1_2 = "GetCurrentProcess" ascii //weight: 1
        $x_1_3 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_4 = "CryptEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazzarldr_GZ_2147765851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazzarldr.GZ!MTB"
        threat_id = "2147765851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazzarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 d0 48 8b [0-2] 48 01 c2 8b 45 [0-2] 48 63 c8 48 8b 45 [0-2] 48 01 c8 0f b6 08 4c 8b 05 [0-4] 0f b6 45 [0-2] 4c 01 c0 0f b6 00 31 c8 88 02 83 45 [0-2] 01 8b 45 [0-2] 3b 45 [0-2] 0f 8c}  //weight: 5, accuracy: Low
        $x_1_2 = "GetCurrentProcess" ascii //weight: 1
        $x_1_3 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_4 = "memcpy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

