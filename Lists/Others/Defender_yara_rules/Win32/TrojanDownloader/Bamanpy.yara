rule TrojanDownloader_Win32_Bamanpy_A_2147710492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bamanpy.A!bit"
        threat_id = "2147710492"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamanpy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pass.txt" wide //weight: 1
        $x_1_2 = "net2ftp.ru" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "badmanproject@ex.ua" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

