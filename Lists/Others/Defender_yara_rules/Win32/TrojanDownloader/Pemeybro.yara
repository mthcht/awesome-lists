rule TrojanDownloader_Win32_Pemeybro_A_2147706052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pemeybro.A"
        threat_id = "2147706052"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pemeybro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 c3 8d 45 f0 50 68 00 10 00 00 68 ?? ?? ?? ?? ff 75 f8 e8 ?? ?? ?? ?? 85 c0 74 0d 8b 45 f0 85 c0 74 06 c6 45 eb 01 eb 04 c6 45 eb 00 8a 45 eb 84 c0 75 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

