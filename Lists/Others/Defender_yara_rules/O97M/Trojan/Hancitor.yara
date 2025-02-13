rule Trojan_O97M_Hancitor_B_2147731155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Hancitor.B"
        threat_id = "2147731155"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "For Output As #" ascii //weight: 1
        $x_1_2 = "Print #" ascii //weight: 1
        $x_1_3 = {77 73 68 2e 52 75 6e 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 01 00 2e 68 74 61 22 2c}  //weight: 1, accuracy: Low
        $x_1_4 = "= fso.CreateTextFile(gdffs & \"6fsdFfa.com\", True)" ascii //weight: 1
        $x_1_5 = "= IsExeRunning(\"n360\" & " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

