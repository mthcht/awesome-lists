rule Trojan_Win32_Captiya_A_2147601411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Captiya.A"
        threat_id = "2147601411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Captiya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Umka\\OCR2\\OCR2.pas" ascii //weight: 1
        $x_5_2 = {8d 85 44 fe ff ff b9 ?? ?? ?? ?? 8b 95 94 fe ff ff e8 ?? ?? f9 ff 8b 85 44 fe ff ff 50 6a 00 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 55 fc 8b 52 04 92 e8 ?? ?? fc ff 8d 45 e0 b9 ?? ?? ?? ?? 8b 95 94 fe ff ff e8 ?? ?? f9 ff 8d 95 3c fe ff ff 8b 45 e0 e8 ?? ?? ff ff ff b5 3c fe ff ff 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 e0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 85 40 fe ff ff ba 06 00 00 00 e8 ?? ?? f9 ff 8b 95 40 fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 85 38 fe ff ff b9 ?? ?? ?? ?? 8b 55 e0 e8 ?? ?? f9 ff 8b 95 38 fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 85 88 fe ff ff e8 ?? ?? f9 ff 89 45 ec 83 7d ec 00 0f 84 2e ff ff ff 33 c0 5a}  //weight: 5, accuracy: Low
        $x_5_3 = {8d 40 00 55 8b ec 83 c4 f4 53 8b d8 33 d2 8b 83 e4 0f 00 00 e8 ?? ?? fb ff 89 45 fc 8b 45 fc 89 43 04 ba 01 00 00 00 8b 83 e4 0f 00 00 e8 ?? ?? fb ff 2b 45 fc 89 45 f4 8b 83 e4 0f 00 00 8b 10 ff 52 20 89 45 f8 56 57 8b 7d fc 8b 4d f8 89 fe 03 7d f4 03 7d f4 03 7d f4 83 e9 07 0f 6f 3d ?? ?? ?? ?? 8b 55 f4 f7 da c1 ea 03 0f 6f 4c d7 f8 0f 6f 44 d6 f8 0f db cf 0f dc c1 0f 7f 44 d6 f8 4a}  //weight: 5, accuracy: Low
        $x_5_4 = {8d 40 00 55 8b ec 6a 00 53 56 8b f2 8b d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 53 68 ?? ?? ?? ?? 8d 45 fc 50 e8 ?? ?? ff ff 8b 45 fc 50 68 ?? ?? ?? ?? 56 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 fc e8 ?? ?? f9 ff c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

