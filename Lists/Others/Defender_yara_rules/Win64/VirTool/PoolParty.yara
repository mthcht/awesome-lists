rule VirTool_Win64_PoolParty_A_2147898363_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/PoolParty.A!MTB"
        threat_id = "2147898363"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolParty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 00 30 00 00 41 b8 f0 00 00 00 48 8b 08 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "PoolPartyEvent" ascii //weight: 1
        $x_1_3 = "RPC Control\\PoolPartyALPCPort" ascii //weight: 1
        $x_1_4 = "PoolPartyJob" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_PoolParty_B_2147898495_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/PoolParty.B!MTB"
        threat_id = "2147898495"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolParty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b b5 60 01 00 00 49 8b 47 10 48 8b 38 48 89 5d f0 48 89 5d 00 48 c7 45 08 0f 00 00 00 41 b8 12 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? e8 ?? ?? ?? ?? 48 89 5c 24 20 41 b9 f0 00 00 00 4c 8b 44 24 60 48 8b d6 48 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b f0 48 89 44 24 48 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b f8 48 89 44 24 50 e8 ?? ?? ?? ?? 44 8b f8 89 44 24 58 41 b8 27 00 00 00 48 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b9 00 30 00 00 41 b8 f0 00 00 00 48 8b 08 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {45 33 c9 45 33 c0 49 8b 55 30 48 8b 0f ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {4c 8b f8 48 89 45 b8 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b f8 48 89 45 c0 e8 ?? ?? ?? ?? 44 8b e0 89 45 c8 41 83 ce 20 41 b8 40 00 00 00 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

