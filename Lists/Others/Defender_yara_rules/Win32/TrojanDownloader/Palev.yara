rule TrojanDownloader_Win32_Palev_A_2147619153_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Palev.A!dll"
        threat_id = "2147619153"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Palev"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 3a 5c 6e 74 6c 6f 61 64 00 00 00 20 00 00 00 20 00 00 00 66 74 70 3a 2f 2f 00 00 3a 00 00 00 40 00 00 00 0a 00 00 00 7a 31 31 31 78 63 00 00 77 73 32 5f 33 32 2e 64 6c 6c 00 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 57 53 41 53 65 6e 64 00 73 65 6e 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

