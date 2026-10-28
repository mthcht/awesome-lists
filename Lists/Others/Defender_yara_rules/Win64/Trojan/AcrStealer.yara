rule Trojan_Win64_AcrStealer_FN_2147980810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.FN!MTB"
        threat_id = "2147980810"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f0 24 88 05}  //weight: 1, accuracy: High
        $x_2_2 = {83 e8 01 0f b6 04 02 0f b6 12 01 d0}  //weight: 2, accuracy: High
        $x_1_3 = "ChromeUpdateMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AcrStealer_HN_2147980869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.HN!MTB"
        threat_id = "2147980869"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 24 88 05}  //weight: 1, accuracy: High
        $x_2_2 = {83 e8 01 0f b6 04 02 0f b6 12 01 d0}  //weight: 2, accuracy: High
        $x_1_3 = "ChromeUpdateMain" ascii //weight: 1
        $x_1_4 = {01 c8 31 c2 81 f2 ?? ?? 00 00 89 d1 81 e1 ?? ?? 00 00 01 c8 89 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AcrStealer_IN_2147981077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.IN!MTB"
        threat_id = "2147981077"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f2 31 c9 44 0f af f0}  //weight: 1, accuracy: High
        $x_2_2 = {89 d1 81 e1 ?? ?? 00 00 01 c1 89 d0 c1 ea 03}  //weight: 2, accuracy: Low
        $x_1_3 = "C:\\Program Files\\x" ascii //weight: 1
        $x_1_4 = {31 c9 ff 15 ?? ?? 01 00 31 c9 0f b6 f8 ff 15 ?? ?? 01 00 31 c9 0f bf f0 ff 15 ?? ?? 01 00 01 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

