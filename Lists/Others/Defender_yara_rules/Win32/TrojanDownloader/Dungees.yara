rule TrojanDownloader_Win32_Dungees_A_2147683937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dungees.A"
        threat_id = "2147683937"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dungees"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 ff d7 8d 44 00 02 50 8b 45 e4 03 45 f8 53 50 e8 d0 fe ff ff 56 68 80 00 00 00 6a 02 56 6a 02 68 00 00 00 40 ff 75 fc}  //weight: 10, accuracy: High
        $x_10_2 = {6a 03 56 56 68 bb 01 00 00 ff 34 85 00 30 00 04 ff 75 e4 ff 15 ?? ?? ?? ?? 8b f8 3b fe}  //weight: 10, accuracy: Low
        $x_1_3 = "/success.exe" wide //weight: 1
        $x_1_4 = "/portrait.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

