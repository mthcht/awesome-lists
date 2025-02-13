rule TrojanDownloader_Win32_Mahost_A_2147662099_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mahost.A"
        threat_id = "2147662099"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mahost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get maj.exe" ascii //weight: 1
        $x_1_2 = "Parcours de" ascii //weight: 1
        $x_1_3 = "%sftp.txt" ascii //weight: 1
        $x_1_4 = "ftp -s:\"%s" ascii //weight: 1
        $x_1_5 = "Le fichier taskhost.exe vient d'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

