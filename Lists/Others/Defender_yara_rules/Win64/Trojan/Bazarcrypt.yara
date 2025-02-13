rule Trojan_Win64_Bazarcrypt_GA_2147765882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazarcrypt.GA!MTB"
        threat_id = "2147765882"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 03 c5 99 41 [0-2] 0f b6 [0-4] 41 [0-2] 4c [0-2] 41 02 [0-4] 41 88 [0-4] 0f b6 c1 88 4c [0-2] 41 0f b6 [0-4] 03 c1 99 41 f7 [0-2] 48 63 [0-2] 49 03 [0-2] 0f b6 [0-2] 41 02 [0-2] 41 32 [0-4] 48 [0-2] 01 88 4e [0-2] 74 [0-8] eb}  //weight: 5, accuracy: Low
        $x_1_2 = "GetCurrentProcess" ascii //weight: 1
        $x_1_3 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazarcrypt_GB_2147765883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazarcrypt.GB!MTB"
        threat_id = "2147765883"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 98 48 03 [0-2] 8b 55 [0-2] 48 63 [0-2] 48 03 [0-2] 0f b6 [0-2] 4c 8b 05 [0-4] 0f b6 [0-2] 4c 01 [0-2] 0f b6 [0-2] 31 ca 88 10 83 45 [0-2] 01 8b 45 [0-2] 3b 45 [0-2] 0f 9c c0 84 c0 0f 85}  //weight: 5, accuracy: Low
        $x_1_2 = "GetCurrentProcess" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazarcrypt_GC_2147765884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazarcrypt.GC!MTB"
        threat_id = "2147765884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 10 8b 2d [0-4] 0f b6 [0-2] 0f b6 [0-2] 03 c2 99 bb [0-4] f7 fb 0f b6 [0-2] 8a 14 [0-2] 8b 44 [0-2] 30 14 07 8b 44 [0-2] 47 3b f8 7c}  //weight: 5, accuracy: Low
        $x_1_2 = "GetCurrentProcess" ascii //weight: 1
        $x_1_3 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_4 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazarcrypt_GD_2147765952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazarcrypt.GD!MTB"
        threat_id = "2147765952"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c1 99 41 f7 [0-2] 8d 1c [0-2] ff 15 [0-4] 44 8a [0-4] 4c 63 [0-2] 49 83 [0-2] 01 41 0f b6 [0-2] 41 02 [0-2] 43 32 [0-4] 48 83 [0-2] 01 41 88 [0-4] 74 09 44 8b [0-6] eb}  //weight: 5, accuracy: Low
        $x_1_2 = "GetCurrentProcess" ascii //weight: 1
        $x_1_3 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazarcrypt_GW_2147766036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazarcrypt.GW!MTB"
        threat_id = "2147766036"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {10 00 00 44 8b [0-2] 33 d2 ff 15 [0-4] 48 8b [0-2] 44 8b [0-2] 48 8d [0-6] 48 8b [0-2] e8 [0-4] 8b 4d [0-2] 89 4c [0-2] 48 8d [0-2] 48 89 [0-4] 48 89 [0-4] 45 33 [0-2] 33 d2 45 8d [0-2] 48 8b [0-2] ff 15 [0-4] 85 c0 0f 84 [0-4] ff d6}  //weight: 5, accuracy: Low
        $x_1_2 = "GetCurrentProcess" ascii //weight: 1
        $x_1_3 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_4 = "CryptEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

