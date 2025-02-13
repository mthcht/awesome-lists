rule Backdoor_Win32_ParallaxRat_KS_2147781754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ParallaxRat.KS!MTB"
        threat_id = "2147781754"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ParallaxRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 4f ec c4 4e f7 e1 c1 ea 03 6b c2 1a 8b d1 2b d0 8a 44 15 e0 30 81 ?? ?? ?? ?? 41 81 f9 00 b0 00 00 72 dc}  //weight: 10, accuracy: Low
        $x_3_2 = "SHGetPathFromIDListA" ascii //weight: 3
        $x_3_3 = "SHGetSpecialFolderLocation" ascii //weight: 3
        $x_3_4 = "GdipCreateBitmapFromHBITMAP" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

