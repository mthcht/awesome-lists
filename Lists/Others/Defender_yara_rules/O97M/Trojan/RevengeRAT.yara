rule Trojan_O97M_RevengeRAT_RDA_2147899852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/RevengeRAT.RDA!MTB"
        threat_id = "2147899852"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "> nul & start C" ascii //weight: 2
        $x_2_2 = "ng 127.0.0.1 -n 10 " ascii //weight: 2
        $x_2_3 = "a.Run (M_S + TOGACDT + M_S1 + M_S2 + M_S3), 0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

