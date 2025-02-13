rule Trojan_O97M_Maldade_RDA_2147900540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Maldade.RDA!MTB"
        threat_id = "2147900540"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Maldade"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CreateObject(\"scrIPtIng.filEsystEMObJect\")" ascii //weight: 2
        $x_2_2 = "CreateObject(\"wSCRipt.SHElL\")" ascii //weight: 2
        $x_2_3 = ".WRiTE StrReverse(" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

