rule TrojanDownloader_Win32_Bambenoy_A_2147624203_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bambenoy.A"
        threat_id = "2147624203"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bambenoy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "enolybabM.tzo.com" wide //weight: 1
        $x_1_2 = "blackjack" wide //weight: 1
        $x_1_3 = "anonymous" wide //weight: 1
        $x_1_4 = "Connection KO" wide //weight: 1
        $x_1_5 = "c:\\cap.jpg" wide //weight: 1
        $x_1_6 = "C:\\test.jpg" wide //weight: 1
        $x_1_7 = "maj.exe" wide //weight: 1
        $x_1_8 = "files.tmp" wide //weight: 1
        $x_1_9 = "\\launch.exe" wide //weight: 1
        $x_1_10 = "\\FtpTest\\FtpTest\\FtpTest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

