rule TrojanDropper_Win64_Lazy_CCJR_2147922861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Lazy.CCJR!MTB"
        threat_id = "2147922861"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 41 b8 08 02 00 00 48 8d 4d c0 e8 ?? ?? ?? ?? ba 04 01 00 00 48 8d 4d c0 ff 15}  //weight: 1, accuracy: Low
        $x_2_2 = {48 63 41 04 48 8b 4c 18 48 48 8b 01 41 b8 00 ?? da 00 48 8d 15 ?? ?? ?? ?? ff 50 48 44 8b c7 ba 04 00 00 00 48 3d 00 ?? da 00 44 0f 45 c2 44 89 84 24 90 00 00 00 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_Lazy_MK_2147954243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Lazy.MK!MTB"
        threat_id = "2147954243"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {41 8b 4c 24 0c 48 8d 54 24 20 41 b8 30 00 00 00 48 01 c1 48 8b 05 c2 93 0c 00 48 89 4c 30 18}  //weight: 15, accuracy: High
        $x_10_2 = {0f b6 43 40 83 63 44 fe 83 e0 f0 83 c8 05 88 43 40 f0 83 05 69 b0 0b 00 01 48 8b 4b 30}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_Lazy_AH_2147964488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Lazy.AH!MTB"
        threat_id = "2147964488"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ProgramData\\Roning\\trustinstaller.bin" ascii //weight: 10
        $x_20_2 = "t^a^s^k^l^i^s^t     /fi    \"PID  eq" ascii //weight: 20
        $x_30_3 = "Microsoft1Edge2Elevation3Service4" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_Lazy_AHA_2147966981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Lazy.AHA!MTB"
        threat_id = "2147966981"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {66 31 04 4a 0f b7 44 24 ?? 48 8d 54 24 ?? 66 31 04 4a 0f b7 44 24 ?? 48 8d 54 24 ?? 66 31 04 4a}  //weight: 30, accuracy: Low
        $x_20_2 = {66 41 31 14 48 0f b7 44 24 ?? 66 31 44 4c ?? 0f b7 44 24 ?? 66 41 31 04 49 0f b7 44 24 ?? 66 41 31 04 4a}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_Lazy_A_2147982388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Lazy.A!MTB"
        threat_id = "2147982388"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {01 fe 88 23 29 fa 48 ff c3 be ?? ?? 00 00 01 ce 01 d7 81 c6 ?? ?? 00 00 b8 ?? ?? 00 00 29 fa 48 2d ?? ?? 00 00 29 ce 48 39 c1 7d}  //weight: 30, accuracy: Low
        $x_20_2 = {29 ce 81 c2 ?? ?? 00 00 8a 23 81 c2 ?? ?? 00 00 01 da c0 c0 ?? 01 ce 01 fe 29 d6 01 fa}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_Lazy_B_2147982389_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Lazy.B!MTB"
        threat_id = "2147982389"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 ff c1 01 f2 81 ?? ?? 4b 00 00 01 fe 8a 23 be ?? ?? 00 00 c0 c0 ?? 81 c6 ?? ?? 00 00 29 cf 30 c4 01 f2 81 c6 ?? ?? 00 00 81 c6 ?? ?? 00 00 88 23 29 df 01 f2 48 ff c3}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

