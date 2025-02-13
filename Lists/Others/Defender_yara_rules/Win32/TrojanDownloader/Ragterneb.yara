rule TrojanDownloader_Win32_Ragterneb_A_2147631861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ragterneb.A"
        threat_id = "2147631861"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragterneb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dev\\_exploit_hosting" wide //weight: 1
        $x_1_2 = "\\download.list" wide //weight: 1
        $x_1_3 = "update.php?locale=" wide //weight: 1
        $x_1_4 = "\\userid.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Ragterneb_B_2147631862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ragterneb.B"
        threat_id = "2147631862"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragterneb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dev\\_win_updater" wide //weight: 1
        $x_1_2 = ".exe /autorun" wide //weight: 1
        $x_1_3 = {75 00 70 00 64 00 61 00 74 00 65 00 5f 00 6c 00 6f 00 67 00 67 00 65 00 72 00 [0-4] 2e 00 70 00 68 00 70 00 3f 00 6c 00 6f 00 63 00 61 00 6c 00 65 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\userid.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

