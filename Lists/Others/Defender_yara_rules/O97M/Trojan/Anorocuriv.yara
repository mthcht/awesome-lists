rule Trojan_O97M_Anorocuriv_AR_2147754391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Anorocuriv.AR!MTB"
        threat_id = "2147754391"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Anorocuriv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(99) + Chr(58) + Chr(92) + Chr(78) + Chr(84) + Chr(99) + Chr(111) + Chr(114) + Chr(101)" ascii //weight: 1
        $x_1_2 = "CreateFile(\"c:\\NTcore\\easy.cmd\"" ascii //weight: 1
        $x_1_3 = " = GetObject(\"new:" ascii //weight: 1
        $x_1_4 = ".Run \"c:\\NTcore\\easy.cmd\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

