rule TrojanDownloader_Win32_Pusrac_A_2147603161_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pusrac.A"
        threat_id = "2147603161"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pusrac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 00 00 00 [0-32] b8 74 00 00 00 [0-32] b8 74 00 00 00 [0-32] b8 70 00 00 00 [0-32] b8 3a 00 00 00 [0-32] b8 2f 00 00 00 [0-32] b8 2f 00 00 00 [0-32] b8 77 00 00 00 [0-32] b8 77 00 00 00 [0-32] b8 77 00 00 00 [0-32] b8 2e 00 00 00 [0-32] b8 66 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 61 00 00 00 [0-32] b8 73 00 00 00 [0-32] b8 74 00 00 00 [0-32] b8 6d 00 00 00 [0-32] b8 70 00 00 00 [0-32] b8 33 00 00 00 [0-32] b8 73 00 00 00 [0-32] b8 65 00 00 00 [0-32] b8 61 00 00 00 [0-32] b8 72 00 00 00 [0-32] b8 63 00 00 00 [0-32] b8 68 00 00 00 [0-32] b8 2e 00 00 00 [0-32] b8 63 00 00 00 [0-32] b8 6f 00 00 00 [0-32] b8 6d 00 00 00 [0-32] b8 2e 00 00 00 [0-32] b8 61 00 00 00 [0-32] b8 72}  //weight: 1, accuracy: Low
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "ShellExecuteExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

