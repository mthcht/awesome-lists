rule Trojan_Win32_Hanictor_VAN_2147789539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hanictor.VAN!MTB"
        threat_id = "2147789539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 e4 c7 45 ?? f0 83 00 00 c7 45 ?? 00 10 00 00 c7 45 ?? 02 00 00 00 c7 45 ?? 7b 00 00 00 33 c0 89 45 c0 89 65 ?? 81 45 ?? b4 00 00 00 89 6d ?? 83 45 ?? 64 8d 0d ?? ?? ?? ?? 8b 41 f0 89 45 f4 8b 41 ec 89 45 f0 c7 45 ?? 01 10 00 00 c7 45 ?? 1e 01 00 00 c7 45 ?? 83 db 8c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 04 89 45 ?? c7 45 ?? 01 10 00 00 c7 45 ?? c4 00 00 00 8b 45 ?? 2d 84 00 00 00 50 8b 45 ?? 48 50 8b 45 ?? 03 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hanictor_FHM_2147794859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hanictor.FHM!MTB"
        threat_id = "2147794859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b c0 44 8b 0d 04 60 04 01 2b c8 0f b7 55 f8 2b d1 66 89 55 f8 a1 04 60 04 01 33 c9 03 05 58 60 04 01 8b 15 5c 60 04 01 13 d1 a3 58 60 04 01 89 15 5c 60 04 01 a1 dc 60 04 01 83 e8 09 2b 05 04 60 04 01 66 89 45 f8}  //weight: 1, accuracy: High
        $x_1_2 = {53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hanictor_VAM_2147798507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hanictor.VAM!MTB"
        threat_id = "2147798507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 0c 83 ee 25 33 35 ?? ?? ?? ?? 81 ee aa 17 67 f3 03 75 14 83 f6 7a 81 ee 0a b3 03 68 89 75 f8 bf 30 00 00 00 89 7d 14}  //weight: 1, accuracy: Low
        $x_1_2 = {33 7d 14 83 ef 6f 33 7d 0c 2b fe 83 c7 5c 81 f7 a0 ef 8b ce 89 7d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

