rule TrojanDownloader_Win32_Kotibu_A_2147651405_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kotibu.A"
        threat_id = "2147651405"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kotibu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".asp?action=install&mac=" wide //weight: 1
        $x_1_2 = {23 00 53 00 74 00 61 00 72 00 74 00 ?? ?? 23 00 68 00 74 00 74 00 70 00 [0-64] 3c 00 45 00 6e 00 64 00 45 00 4f 00 53 00 3e 00}  //weight: 1, accuracy: Low
        $x_1_3 = "winmgmts:\\\\.\\root\\cimv2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

