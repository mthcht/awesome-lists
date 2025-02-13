rule TrojanDownloader_Win32_Revosh_A_2147706568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Revosh.A"
        threat_id = "2147706568"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Revosh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "76.191.112.2/recv.php" wide //weight: 2
        $x_2_2 = "name=\"uploadfile\"; filename=\"" wide //weight: 2
        $x_1_3 = "RemoteShot" ascii //weight: 1
        $x_1_4 = "shot.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

