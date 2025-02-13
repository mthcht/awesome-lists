rule Backdoor_Win64_CobaltStrikeLoader_G_2147781898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CobaltStrikeLoader.G!MTB"
        threat_id = "2147781898"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0e 0f b6 c0 83 e8 [0-1] 6b c0 [0-1] 99 f7 ff 8d 04 17 99 f7 ff 88 14 0e 46 83 fe [0-1] 72 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 37 0f b6 c0 6a [0-1] 59 2b c8 6b c1 [0-1] 99 f7 fb 8d 04 13 99 f7 fb 88 14 37 47 83 ff [0-1] 72 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win64_CobaltStrikeLoader_ES_2147812348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CobaltStrikeLoader.ES!dha"
        threat_id = "2147812348"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 01 d0 0f b6 00 89 c1 8b 85 ?? ?? ?? ?? 99 f7 bd ?? ?? ?? ?? 89 d0 48 98 0f b6 84 05 ?? ?? ?? ?? 31 c1 8b 85 ?? ?? ?? ?? 48 98 48 8b 95 ?? ?? ?? ?? 48 01 d0 89 ca 88 10 83 85}  //weight: 5, accuracy: Low
        $x_4_2 = {49 89 c8 48 89 c1 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 48 8d 85 ?? ?? ?? ?? 48 89 44 24 ?? c7 44 24 ?? ?? ?? ?? ?? 41 b9 00 00 00 00 49 89 d0 ba 00 00 00 00 b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_CobaltStrikeLoader_IP_2147821463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CobaltStrikeLoader.IP!dha"
        threat_id = "2147821463"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "252.72.131.228" ascii //weight: 1
        $x_1_2 = "240.232.200.0" ascii //weight: 1
        $x_1_3 = "0.0.65.81" ascii //weight: 1
        $x_1_4 = "65.80.82.81" ascii //weight: 1
        $x_1_5 = "86.72.49.210" ascii //weight: 1
        $x_1_6 = "101.72.139.82" ascii //weight: 1
        $x_1_7 = "RtlIpv4StringToAddressA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_CobaltStrikeLoader_HCC_2147832103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CobaltStrikeLoader.HCC!dha"
        threat_id = "2147832103"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 89 c0 e8 6a 00 00 00 48 3d f0 49 12 00 74 04}  //weight: 1, accuracy: High
        $x_1_2 = {48 6b d2 0a 48 0f b6 08 48 83 e9 30 48 ff c0 48 01 ca 80 38 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

