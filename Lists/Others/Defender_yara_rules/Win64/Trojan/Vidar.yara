rule Trojan_Win64_Vidar_PC_2147887433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.PC!MTB"
        threat_id = "2147887433"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f7 d3 ee 03 c7 89 45 e0 c7 05 84 39 92 01 ee 3d ea f4 03 75 d0 8b 45 e0 31 45 f8 33 75 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_UL_2147892926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.UL!MTB"
        threat_id = "2147892926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d6 d3 ea 8d 04 37 89 45 e8 c7 05 a8 a6 61 00 ee 3d ea f4 03 55 dc 8b 45 e8 31 45 fc 33 55 fc 81 3d 10 b1 61 00 13 02 00 00 89 55 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_AB_2147893043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.AB!MTB"
        threat_id = "2147893043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 8b c8 c1 ea 05 03 54 24 28 c1 e1 04 03 4c 24 2c 03 c7 33 d1 33 d0 2b f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_PSD_2147899275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.PSD!MTB"
        threat_id = "2147899275"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 89 f0 48 89 81 b8 ?? ?? ?? 48 8b 44 24 30 48 89 81 a8 ?? ?? ?? 48 8d 44 24 38 48 89 81 b0 ?? ?? ?? b8 01 ?? ?? ?? eb 02 31 c0 48 89 4c 24 20 88 44 24 1f 48 8b 15 b8 ?? ?? ?? 48 89 14 24 48 8d 91 78 ?? ?? ?? 48 89 54 24 08 e8 83 e5 02 00 45 0f 57 ff}  //weight: 5, accuracy: Low
        $x_1_2 = "MapKeys" ascii //weight: 1
        $x_1_3 = "runtime.persistentalloc" ascii //weight: 1
        $x_1_4 = "CoreDump" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_CCFX_2147899887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.CCFX!MTB"
        threat_id = "2147899887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 49 64 41 03 89 ?? ?? ?? ?? 41 8b 91 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 0f af c1 81 c2 ?? ?? ?? ?? 41 89 41 0c 41 03 51 40 41 8b 81 ?? ?? ?? ?? 0f af c2 41 89 81 ?? ?? ?? ?? 49 81 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_AVI_2147937730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.AVI!MTB"
        threat_id = "2147937730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c2 45 69 c0 ?? ?? ?? ?? 8b c8 c1 e9 18 33 c8 69 c9 ?? ?? ?? ?? 44 33 c1 48 3b d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_SLAE_2147941890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.SLAE!MTB"
        threat_id = "2147941890"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 05 ee 9b 03 00 8d 48 ff 0f af c8 f6 c1 01 b8 58 b2 7a ac 41 0f 44 c5 83 3d d9 9b 03 00 0a 41 0f 4c c5 3d 8d 96 34 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_BOZ_2147944027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.BOZ!MTB"
        threat_id = "2147944027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 48 8b 4d b0 8a 04 01 48 63 4d ?? 48 8b 55 88 30 04 0a 44 8b 5d ?? 41 83 c3 01 b8 c1 04 f3 84 44 8b 4d a0 4c 8b 45 80 44 8b 75 ?? 44 8b 6d 94 8b 5d 98 3d 12 dd 65 dd 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_ARA_2147952226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.ARA!MTB"
        threat_id = "2147952226"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 0f b6 08 ff c2 83 e1 0f 4a 0f be 84 11 e0 54 01 00 42 8a 8c 11 f0 54 01 00 4c 2b c0 41 8b 40 fc d3 e8 4c 89 47 08 89 47 18 41 0f b6 08 83 e1 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

