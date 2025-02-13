rule TrojanDownloader_Win32_Krepper_2147799824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Krepper"
        threat_id = "2147799824"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Krepper"
        severity = "12"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "fuck off, buddy" ascii //weight: 5
        $x_3_2 = "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\Microsoft Office.hta" ascii //weight: 3
        $x_2_3 = "C:\\web.exe" ascii //weight: 2
        $x_3_4 = "5321E378-FFAD-4999-8C62-03CA8155F0B3}\\VersionIndependentProgID" ascii //weight: 3
        $x_2_5 = "&program=7&variable=check&value=" ascii //weight: 2
        $x_2_6 = "&program=7&variable=get" ascii //weight: 2
        $x_2_7 = "traff-store.com/gallerysponsor/xpsystem/" ascii //weight: 2
        $x_2_8 = "affcgi/online.fcgi?%ACCOUNT%" ascii //weight: 2
        $x_2_9 = "affiliate/interface.php?userid=" ascii //weight: 2
        $x_2_10 = "mm.exe mm4.exe %ACCOUNT%" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

