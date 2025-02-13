rule TrojanDownloader_Win32_Daws_A_2147695851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Daws.A"
        threat_id = "2147695851"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Daws"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 02 83 e2 03 83 f9 08 72 ?? f3 a5 ff 24 95 [0-4] 8b c7 ba 03 00 00 00 83 e9 04 72 ?? 83 e0 03 03 c8 ff 24 85}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Windows\\lshost.exe" ascii //weight: 1
        $x_1_3 = "SpyProject\\Release\\Launcher.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

