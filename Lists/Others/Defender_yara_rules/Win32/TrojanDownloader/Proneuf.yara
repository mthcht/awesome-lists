rule TrojanDownloader_Win32_Proneuf_A_2147709689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Proneuf.A!bit"
        threat_id = "2147709689"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Proneuf"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "URLDownloadToFileA" ascii //weight: 2
        $x_2_2 = "D:\\$RECYCLEBIN\\test" wide //weight: 2
        $x_2_3 = "D:\\$RECYCLEBIN\\rabbit" wide //weight: 2
        $x_1_4 = {2d 00 24 00 52 00 45 00 43 00 59 00 43 00 4c 00 45 00 42 00 49 00 4e 00 5c 00 [0-32] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = "D:\\$RECYCLEBIN\\trash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

