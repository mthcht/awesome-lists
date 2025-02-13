rule TrojanDownloader_Win32_Bitter_A_2147740966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bitter.A"
        threat_id = "2147740966"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET ///healthne/accept.php" ascii //weight: 1
        $x_1_2 = "7f5ed85d-6828-4f92-858c-f40b0ac68138" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

