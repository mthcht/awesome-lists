rule TrojanDownloader_O97M_Exoidovn_A_2147913144_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Exoidovn.A"
        threat_id = "2147913144"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Exoidovn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ll1 = DateAdd(\"d\", l1l, IIl)" ascii //weight: 1
        $x_1_2 = " = GetObject(\"new:msxml2.domdocument\")" ascii //weight: 1
        $x_1_3 = ".LoadXML UserForm1.Label1.Caption" ascii //weight: 1
        $x_1_4 = ".transformnode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

