rule Worm_Win32_Egapel_C_2147639545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Egapel.C"
        threat_id = "2147639545"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Egapel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 f8 05 7c ed c6 06 e9 89 7e 01}  //weight: 5, accuracy: High
        $x_5_2 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 57 00}  //weight: 5, accuracy: High
        $x_1_3 = "RECYCLER.lnk" wide //weight: 1
        $x_1_4 = "pagefile.sys.lnk" wide //weight: 1
        $x_1_5 = "boot.ini.lnk" wide //weight: 1
        $x_1_6 = "IO.SYS.lnk" wide //weight: 1
        $x_1_7 = "NTDETECT.COM.lnk" wide //weight: 1
        $x_1_8 = "System Volume Information.lnk" wide //weight: 1
        $x_1_9 = "destop.ini.lnk" wide //weight: 1
        $x_1_10 = "WCH.CN.lnk" wide //weight: 1
        $x_1_11 = "winnt.bmp.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

