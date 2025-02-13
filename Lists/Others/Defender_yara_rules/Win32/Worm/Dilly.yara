rule Worm_Win32_Dilly_A_2147615327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dilly.A"
        threat_id = "2147615327"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dilly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "ShellExecute" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Magnet\\Handlers" ascii //weight: 1
        $x_1_4 = "Settings\\DcPlusPlus.xml" ascii //weight: 1
        $x_1_5 = "<Directory Virtual=\"auto_disk_share_" ascii //weight: 1
        $x_1_6 = "del /Q %0" ascii //weight: 1
        $x_1_7 = "c:\\_undo_" ascii //weight: 1
        $x_1_8 = ".WMV.scr" ascii //weight: 1
        $x_1_9 = ".AVI.scr" ascii //weight: 1
        $x_1_10 = ".MPG.scr" ascii //weight: 1
        $x_1_11 = {ff ff ff ff 04 00 00 00 68 61 72 64 00 00 00 00 ff ff ff ff 04 00 00 00 70 6f 72 6e 00 00 00 00 ff ff ff ff 03 00 00 00 61 73 73 00 ff ff ff ff 05 00 00 00 64 69 6c 64 6f 00 00 00 ff ff ff ff 06 00 00 00 69 6e 63 65 73 74 00 00 ff ff ff ff 04 00 00 00 70 65 64 6f 00 00 00 00 ff ff ff ff 06 00 00 00 66 75 63 6b 65 64 00 00 ff ff ff ff 04 00 00 00 70 69 73 73 00 00 00 00 ff ff ff ff 05 00 00 00 6c 65 73 62 69 00 00 00 ff ff ff ff 05 00 00 00 67 69 72 6c 73 00 00 00 ff ff ff ff 06 00 00 00 61 6e 67 65 6c 73 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

