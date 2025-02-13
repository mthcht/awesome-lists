rule TrojanProxy_Win32_Kabwall_A_2147609257_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Kabwall.A"
        threat_id = "2147609257"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kabwall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 05 00 00 00 e8 ?? ?? ?? ff b8 09 00 00 00 e8 ?? ?? ?? ff 8b f0 8d 55 f8 8b c6 e8 ?? ?? ?? ff 8b 55 f8 8d 45 fc e8 ?? ?? ?? ff 4b 75 d7}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 7b 0a a5 a5 a5 a5 5f 5e 89 73 04 66 c7 43 08 3c 00 53 e8 ?? ?? ?? ff 84 c0 74 08 3c 06 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {84 c0 75 29 ff 45 c4 83 7d c4 1e 7e 0d 8b 45 fc e8 ?? ?? ?? ff e9 ?? ?? 00 00 68 88 13 00 00 e8 ?? ?? ?? ff 8b 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

