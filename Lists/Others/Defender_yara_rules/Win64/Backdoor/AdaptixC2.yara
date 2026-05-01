rule Backdoor_Win64_AdaptixC2_MK_2147961854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/AdaptixC2.MK!MTB"
        threat_id = "2147961854"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "AdaptixC2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_25_1 = {48 83 ec 10 89 4d 10 c7 ?? ?? ?? ?? ?? ?? 8b 45 10 89 45 f8 48 8d 45 fc 0f b6 00 3c dd 75 37 48 8d 45 f8 0f b6 55 13 88 10 48 8d 45 f8 48 83 c0 01 0f b6 55 12 88 10 48 8d 45 f8 48 83 c0 02}  //weight: 25, accuracy: Low
        $x_15_2 = {83 c0 02 89 c2 b8 ab aa aa aa 48 0f af c2 48 c1 e8 20 d1 e8 c1 e0 02 83 c0 01 89 45 fc 8b 45 fc 48 89 c2 b9 40}  //weight: 15, accuracy: High
        $x_10_3 = "cmd.exe /c start \"\" /B %s" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_AdaptixC2_MKA_2147966582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/AdaptixC2.MKA!MTB"
        threat_id = "2147966582"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "AdaptixC2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 89 c2 48 8b 05 ?? ?? ?? ?? 48 89 90 ?? ?? ?? 00 48 8b 45 f8 ba 44 b1 52 16 48 89 c1 e8 ?? ?? ?? ?? 48 89 c2 48 8b 05 ?? ?? ?? ?? 48 89 90 ?? ?? ?? 00 48 8b 45 f8 ba 24 5c 07 90 48 89 c1}  //weight: 20, accuracy: Low
        $x_15_2 = {89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 55 fc 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 00 0f b6 d0 8b 45 f8 01 c2 89 d0}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_AdaptixC2_MKB_2147967807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/AdaptixC2.MKB!MTB"
        threat_id = "2147967807"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "AdaptixC2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 8b 00 4c 8b ?? ?? ?? ?? ?? 4c 8b 45 f0 8b 45 fc 83 c0 ?? 48 63 d0 48 8b 45 10 48 8b 40 ?? 48 8b 4d 18 4d 89 c1 49 89 c8 48 89 c1 41 ff d2 48 8b 45 10 8b 50 10 8b 45 fc 01 c2 48 8b 45 10 89 50 ?? 48 8b 45 10 48 8b}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_AdaptixC2_KK_2147968228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/AdaptixC2.KK!MTB"
        threat_id = "2147968228"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "AdaptixC2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {33 d2 48 8d 49 01 8b c7 ff c7 41 f7 f0 42 0f b6 04 0a 30 41 ff 3b fe}  //weight: 20, accuracy: High
        $x_10_2 = {0f b7 c2 48 83 c6 04 89 43 02 c7 43 fe 4c 8b d1 b8 66 c7 43 06 49 bb 48 89 7b 08 66 c7 43 10 41 ff c6 43 12 e3 48 83 c3 15 49 3b f5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

