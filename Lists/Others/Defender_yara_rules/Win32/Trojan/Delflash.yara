rule Trojan_Win32_Delflash_A_2147688759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delflash.A"
        threat_id = "2147688759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delflash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 6a 00 8b c3 2d 87 9a 08 00 50 6a 00 8b c3 2d 89 9a 08 00 50 81 c3 76 65 f7 7f 53 8b 45 fc e8 ?? ?? ?? ?? 50 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {b8 03 2c 32 0f 3d 14 ec cc 2a 0f 85 3a 02 00 00}  //weight: 5, accuracy: High
        $x_1_3 = {ff 47 43 4e 20 00 89 45 ?? 8a 03 8b 55 ?? 8b 4d ?? 8a 94 0a 00 ff ff ff 88 13 8b 55 ?? 8b 4d ?? 88 84 0a 00 ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = "Borland\\Delphi\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

