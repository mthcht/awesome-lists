rule Trojan_Win32_Doohy_A_2147628038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doohy.A"
        threat_id = "2147628038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doohy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 34 6a 00 8d 85 ?? ?? ff ff 50 68 00 02 00 00 8d 8d ?? ?? ff ff 51 8b 95 ?? ?? ff ff 52 ff 15 ?? ?? 40 00 8b 85 ?? ?? ff ff 50 ff 15 ?? ?? 40 00 e9 e0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7d ec 00 74 27 6a 40 68 00 10 00 00 6a 15 8b ?? ?? c1 e2 0c 52 8b 45 08 50 ff 15 ?? ?? 40 00 89 45 fc 83 7d fc 00 74 02 eb 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

