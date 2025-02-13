rule Trojan_Win32_Vidsrs_A_2147600523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidsrs.A"
        threat_id = "2147600523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidsrs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ff 55 89 e5 83 ed 1c 5d 60 e8 ff ff ff ff c0 5d 83 ed 0f b9 00 00 10 00 50 89 e8 8b 00 5b e2 f8}  //weight: 1, accuracy: High
        $x_1_2 = {c6 01 68 8d 83 ?? ?? 00 00 89 41 01 c6 41 05 c3 b9 44 00 00 00 31 c0 8d bd ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

