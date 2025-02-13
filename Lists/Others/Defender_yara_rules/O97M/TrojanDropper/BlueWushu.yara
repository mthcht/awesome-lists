rule TrojanDropper_O97M_BlueWushu_A_2147730500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/BlueWushu.A"
        threat_id = "2147730500"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "BlueWushu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tempfilename = Environ(\"temp\") & \"\\share.exe\"" ascii //weight: 1
        $x_1_2 = "writebytes f, \"4d 5a 90" ascii //weight: 1
        $x_1_3 = "Shell Environ(\"temp\") & \"\\share.exe\"" ascii //weight: 1
        $x_1_4 = "Public Sub writebytes(file, bytes)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

