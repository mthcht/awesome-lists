rule Trojan_Win32_Lydra_AS_2147925471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lydra.AS!MTB"
        threat_id = "2147925471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lydra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 45 fc 8a 44 30 ff 8b d0 c1 e2 06 25 ff 00 00 00 c1 e8 02 0a c2 33 db 8a d8 8b c6 25 ff 00 00 00 33 d8 83 eb 0c 85 db 7d 06 81 c3 00 01 00 00 81 f3 c2 00 00 00 81 eb f6 00 00 00 85 db 7d 06 81 c3 00 01 00 00 83 f3 62 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b 45 f8 e8 ?? ?? ?? ?? 8b 45 f8 46 4f 75}  //weight: 4, accuracy: Low
        $x_1_2 = "78l9AnBICGKLW4cNOZm3jPQRUVXJYgbdFM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

