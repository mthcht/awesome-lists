rule Trojan_Win32_Smokeloadder_GFW_2147843251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloadder.GFW!MTB"
        threat_id = "2147843251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloadder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d6 c1 ea ?? 03 54 24 ?? 03 fe 31 7c 24 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 4d 8b 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

