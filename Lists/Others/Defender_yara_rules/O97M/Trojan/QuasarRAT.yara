rule Trojan_O97M_QuasarRAT_RDA_2147925218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/QuasarRAT.RDA!MTB"
        threat_id = "2147925218"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "w = Mid(enc, y, 1)" ascii //weight: 2
        $x_2_2 = "AppData = AppData & Chr(Asc(w) - 1)" ascii //weight: 2
        $x_2_3 = "enc = StrReverse(enc)" ascii //weight: 2
        $x_2_4 = "Decryptinkn = AppData" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

