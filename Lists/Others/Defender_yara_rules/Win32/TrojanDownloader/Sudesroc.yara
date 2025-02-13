rule TrojanDownloader_Win32_Sudesroc_A_2147705954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sudesroc.A"
        threat_id = "2147705954"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sudesroc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ww.ussoccerkit.com/min" wide //weight: 2
        $x_2_2 = "/lib/Surf.zip" wide //weight: 2
        $x_2_3 = "deus@55" wide //weight: 2
        $x_1_4 = "\\ereadersaw.exe" wide //weight: 1
        $x_1_5 = "\\liscu.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

