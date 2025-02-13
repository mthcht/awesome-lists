rule TrojanDownloader_Win32_Spudashup_A_2147638883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spudashup.A"
        threat_id = "2147638883"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spudashup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 64 00 73 00 65 00 72 00 76 00 65 00 72 00 [0-6] 2e 00 66 00 69 00 6c 00 65 00 61 00 76 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 68 00 6f 00 77 00 61 00 64 00 73 00 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 69 6c 65 6e 74 00 00 73 68 6f 77 74 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

