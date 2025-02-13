rule Trojan_O97M_Malgent_F_2147735869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Malgent.F"
        threat_id = "2147735869"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = Array(\"process explorer\", \"processhacker\", \"procmon\", \"visual basic\", \"fiddler\", \"wireshark\")" ascii //weight: 1
        $x_1_2 = "Call aeLhwrtr(dcoe(bWLaPthArr))" ascii //weight: 1
        $x_1_3 = "path_file = Environ$(\"USERPROFILE\") + \"\\AppData\\Roaming\\\" + \"\\\" + path_dom + a + b + c" ascii //weight: 1
        $x_1_4 = "path_file = Environ$(\"USERPROFILE\") & \"\\AppData\\\" + path_dom + \".ttp\"" ascii //weight: 1
        $x_1_5 = {56 61 72 69 61 62 6c 65 32 2e 73 61 76 65 74 6f 66 69 6c 65 20 22 32 33 34 2e 65 22 20 26 20 22 78 65 22 2c 20 32 0d 0a 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 52 65 70 6c 61 63 65 28 55 73 65 72 46 6f 72 6d 31 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

