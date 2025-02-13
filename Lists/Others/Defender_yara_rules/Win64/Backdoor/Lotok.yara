rule Backdoor_Win64_Lotok_GMF_2147891716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Lotok.GMF!MTB"
        threat_id = "2147891716"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 8b ce 44 2b cf 41 ff c1 41 f7 f9 45 8b 08 8d 04 17 8b d6 48 98 49 8d 0c 86 41 8b 04 86 41 89 00 4d 8b c6 44 89 09 8b cf}  //weight: 10, accuracy: High
        $x_10_2 = {66 89 45 d8 0f b6 05 8e 46 24 00 f2 0f 11 45 d0 0f 29 4d c0 88 45 da}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Lotok_GLX_2147913212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Lotok.GLX!MTB"
        threat_id = "2147913212"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 8b f5 0f b7 43 14 48 8d 0d ?? ?? ?? ?? 48 03 c6 4c 89 6c 24 20 44 8b 44 18 2c 8b 54 18 24 4c 03 c1 48 8b 4c 24 68 49 03 d6 44 8b 4c 18 28 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

