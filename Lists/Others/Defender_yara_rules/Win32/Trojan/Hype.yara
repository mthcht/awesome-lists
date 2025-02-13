rule Trojan_Win32_Hype_DSK_2147744214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hype.DSK!MTB"
        threat_id = "2147744214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hype"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 1a 88 14 01 8a 8b ?? ?? ?? ?? 84 c9 75 ?? 8b 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 03 cb 03 c1 30 10 83 3d ?? ?? ?? ?? 03 76}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

