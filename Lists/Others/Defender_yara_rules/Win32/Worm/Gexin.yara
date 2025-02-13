rule Worm_Win32_Gexin_A_2147600935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gexin.A"
        threat_id = "2147600935"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gexin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 0b 8d 95 ?? ?? ff ff 33 c9 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 95 ?? ?? ff ff 8d 85 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff ba ?? ?? ?? ?? 8d 85 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff 8d 85 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff 8d 85 ?? ?? ff ff 33 c9 ba 44 00 00 00 e8 ?? ?? ff ff c7 85 ?? ?? ff ff 01 00 00 00 66 c7 85 ?? ?? ff ff 00 00 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 6a 00 6a 00 6a 40 6a 00 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff ba 03 00 00 00 e8 ?? ?? ff ff 8d 85 ?? ?? ff ff ba 02 00 00 00 e8 ?? ?? ff ff 8d 45 fc e8 ?? ?? ff ff c3 e9 ?? ?? ff ff eb d0 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = "CheckedValue /t REG_SZ /d 0 /f" ascii //weight: 1
        $x_1_4 = "CheckedValue /t REG_dword /d 00000002 /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

