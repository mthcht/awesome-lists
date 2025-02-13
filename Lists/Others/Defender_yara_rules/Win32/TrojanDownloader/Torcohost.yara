rule TrojanDownloader_Win32_Torcohost_A_2147679390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Torcohost.A"
        threat_id = "2147679390"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Torcohost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 b7 81 e0 af 81 c2 f4 34 00 00 52 e8 ?? ?? ?? ?? 85 c0 0f 85 ?? 00 00 00 [0-7] 8b ?? 24 [0-8] 6b c9 (63|69) 05 f4 34 00 00 50 81 c1 ?? ?? 41 00 51 e8}  //weight: 10, accuracy: Low
        $x_1_2 = {ff d2 50 8b 06 57 ff d0 85 c0 0f 84 ?? ?? 00 00 8b 35 ?? ?? ?? ?? 53 53 53 53 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 8e ?? ?? 00 00 50 ff d1 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

