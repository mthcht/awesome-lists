rule TrojanDownloader_Win32_Silky_A_2147650454_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Silky.A"
        threat_id = "2147650454"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Silky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 74 74 70 3a 2f 2f [0-101] 63 6d 64 20 2f 6b 20 63 3a 5c 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 00 55 8b ec 6a 00 33 c0 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

