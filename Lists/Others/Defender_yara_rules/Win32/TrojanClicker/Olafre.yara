rule TrojanClicker_Win32_Olafre_A_2147624202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Olafre.A"
        threat_id = "2147624202"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Olafre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://cbl.toolbar4free.com/cgi-bin/s.exe" ascii //weight: 1
        $x_1_2 = {64 ff 30 64 89 20 8b d6 b8 ?? ?? 45 00 e8 ?? ?? ?? ff 85 c0 7e 0c 8d 45 ?? 8b d6 e8 ?? ?? ?? ff eb 0f 8d 45 fc 8b ce ba ?? ?? 45 00 e8 ?? ?? ?? ff 84 db 0f 84 1e 01 00 00 6a 00 8d 45 ?? 50 33 c9 ba ?? ?? 45 00 b8 00 00 00 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

