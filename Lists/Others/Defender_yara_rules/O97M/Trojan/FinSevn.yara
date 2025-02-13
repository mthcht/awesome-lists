rule Trojan_O97M_FinSevn_A_2147752452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/FinSevn.A!MTB"
        threat_id = "2147752452"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FinSevn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MsgBox (\"Document decrypt error.\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

