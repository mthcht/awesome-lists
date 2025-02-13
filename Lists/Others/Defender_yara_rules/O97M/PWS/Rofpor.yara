rule PWS_O97M_Rofpor_A_2147688301_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:O97M/Rofpor.A"
        threat_id = "2147688301"
        type = "PWS"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Rofpor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dmforever.biz/reporter.php?msg=\" & message_no_spaces & \"&uname=\" & username_no_spaces & \"&pword=" ascii //weight: 1
        $x_1_2 = "Call uploadPOST(\"NULL\", \"NULL\", \"MACRO_EXECUTED_WORD_P_ONLY\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

