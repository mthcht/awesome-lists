rule Worm_Win32_MoonLight_GZZ_2147905450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/MoonLight.GZZ!MTB"
        threat_id = "2147905450"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "MoonLight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {21 13 31 df 47 ?? ?? 5f 1b 69 46 25 ?? ?? ?? ?? 30 5b 09 5e 22 c0 b4 5a e2}  //weight: 5, accuracy: Low
        $x_5_2 = {33 0e 09 2a 0a d1 89 45 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

