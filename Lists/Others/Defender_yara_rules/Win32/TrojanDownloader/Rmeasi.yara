rule TrojanDownloader_Win32_Rmeasi_A_2147666212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rmeasi.A"
        threat_id = "2147666212"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rmeasi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 76 62 73 0a 65 63 68 6f 20 45 58 49 54 20 3e 3e 20 72 65 65 6d 2e 62 61 74}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? c7 45 ?? cf 07 00 00 eb 81 7d 01 cf 07 00 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

