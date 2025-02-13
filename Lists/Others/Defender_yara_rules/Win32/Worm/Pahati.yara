rule Worm_Win32_Pahati_A_2147609939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pahati.A"
        threat_id = "2147609939"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pahati"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "94"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "D:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 10
        $x_10_2 = "E:\\auntiviroes\\wormku\\WordVir\\alonso.vbp" wide //weight: 10
        $x_10_3 = "C:\\System Volume Information\\WORD32.EXE" wide //weight: 10
        $x_10_4 = "Patah Hati.doc" wide //weight: 10
        $x_10_5 = "File2.Path & File2.List(j).doc .exe" wide //weight: 10
        $x_10_6 = "wscript.shell" wide //weight: 10
        $x_10_7 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\runonce\\" wide //weight: 10
        $x_10_8 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\advanced\\HideFileExt" wide //weight: 10
        $x_10_9 = "WordVir" ascii //weight: 10
        $x_1_10 = "tmrFlasdisk" ascii //weight: 1
        $x_1_11 = "removable" wide //weight: 1
        $x_1_12 = "drive fixed" wide //weight: 1
        $x_1_13 = "remote" wide //weight: 1
        $x_1_14 = "cd-rom" wide //weight: 1
        $x_1_15 = "ramdisk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

