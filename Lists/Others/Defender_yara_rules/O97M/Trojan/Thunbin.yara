rule Trojan_O97M_Thunbin_A_2147742465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Thunbin.A"
        threat_id = "2147742465"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Thunbin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Shell.Application" ascii //weight: 1
        $x_1_2 = ".Open" ascii //weight: 1
        $x_1_3 = ".Status = 200 Then" ascii //weight: 1
        $x_1_4 = ".SaveToFile" ascii //weight: 1
        $x_1_5 = "= 10 - 9" ascii //weight: 1
        $x_1_6 = {69 75 75 71 74 3b 30 30 75 69 66 2f 66 62 73 75 69 2f 6d 6a 30 7f 74 68 75 62 75 69 62 6e 30 71 76 75 75 7a 30 31 2f 38 33 30 78 34 33 30 71 76 75 75 7a 2f 66 79 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

