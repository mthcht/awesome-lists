rule Trojan_Win32_LummaSrealer_KPR_2147966604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaSrealer.KPR!MTB"
        threat_id = "2147966604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaSrealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 04 b9 47 8b 45 ?? 8b 04 b8 85 c0 74 ?? 89 45 ?? f7 d0 0d ?? ?? ?? ?? 3d ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {41 88 e3 80 e4 ?? f6 d3 80 e3 ?? 08 dc 80 f4 ?? 88 64 15 ?? 42 84 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaSrealer_KG_2147966672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaSrealer.KG!MTB"
        threat_id = "2147966672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaSrealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 b4 2c ?? ?? ?? ?? 8d bc 04 ?? ?? ?? ?? 0f b6 7c 3d ?? 0f b6 94 2c ?? ?? ?? ?? 31 fa 31 d6 96 88 84 2c ?? ?? ?? ?? 96 45 8b 94 24 ?? ?? ?? ?? 83 fd ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

