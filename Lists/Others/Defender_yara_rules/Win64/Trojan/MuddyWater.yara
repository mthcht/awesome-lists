rule Trojan_Win64_MuddyWater_DA_2147956534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MuddyWater.DA!MTB"
        threat_id = "2147956534"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MuddyWater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 04 24 b9 20 00 00 00 48 f7 f1 48 8b c2 48 8b 4c 24 30 0f b6 04 01 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 88 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MuddyWater_DC_2147956536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MuddyWater.DC!MTB"
        threat_id = "2147956536"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MuddyWater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "phoenixV4\\phoenixV3\\phoenixV2\\x64\\Debug\\phoenix.pdb" ascii //weight: 10
        $x_5_2 = "fdasfasdfgasgsdf" ascii //weight: 5
        $x_5_3 = "sjdhfgvhsadgjfgh" ascii //weight: 5
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "RaiseException" ascii //weight: 1
        $x_1_6 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_MuddyWater_GVF_2147961012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MuddyWater.GVF!MTB"
        threat_id = "2147961012"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MuddyWater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 f9 13 77 26 0f b6 54 31 02 c1 e2 10 44 0f b7 04 31 44 01 c2 81 c2 00 00 00 f0 33 14 08 89 94 0c 80 01 00 00 48 83 c1 04 eb d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MuddyWater_GVG_2147961013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MuddyWater.GVG!MTB"
        threat_id = "2147961013"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MuddyWater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 fa 0b 77 2b 44 0f b6 44 0a 02 41 c1 e0 10 44 0f b7 0c 0a 45 01 c8 41 81 c0 00 00 00 c9 44 33 04 10 44 89 84 15 b0 0e 00 00 48 83 c2 04 eb cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

