rule Trojan_Win32_Dizemp_GKL_2147852271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dizemp.GKL!MTB"
        threat_id = "2147852271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dizemp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 40 0c 8b 00 8b 00 b9 ?? ?? ?? ?? 33 c1 89 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 83 e9 ?? 86 e9 66 89 8d ?? ?? ?? ?? 66 c7 85 ?? ?? ?? ?? ?? ?? 6a 10 8d 8d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

