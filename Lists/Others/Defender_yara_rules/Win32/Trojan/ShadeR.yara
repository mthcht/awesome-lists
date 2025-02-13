rule Trojan_Win32_ShadeR_SA_2147745460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadeR.SA!MTB"
        threat_id = "2147745460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadeR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 2e 68 [0-16] 88 54 24 43 [0-16] 00 00 74 [0-32] 8b 0d ?? ?? ?? ?? 8a 54 24 3b 88 14 0e 46 3b f3 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

