rule Worm_Win32_Knupiex_A_2147681811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Knupiex.A"
        threat_id = "2147681811"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Knupiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&act=post&al=1&facebook_export=&fixed=&friends_only=" ascii //weight: 1
        $x_1_2 = {33 d2 f3 a6 0f 85 ?? ?? 00 00 6a 3b 8b 85 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 83 c4 08 89 85 ?? ?? ff ff 8b 4d 0c 89 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 83 c2 01 89 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 8a 08 88 8d ?? ?? ff ff 83 85 ?? ?? ff ff 01 80 bd ?? ?? ff ff 00 75 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

