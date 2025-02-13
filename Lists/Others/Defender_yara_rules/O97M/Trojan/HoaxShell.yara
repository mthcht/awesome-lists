rule Trojan_O97M_HoaxShell_RDA_2147900675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/HoaxShell.RDA!MTB"
        threat_id = "2147900675"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "HoaxShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JABzAD0AJwAxADkAMgAuADEANgA4AC4AMgAyADkALgAxADMAMQA6ADgAMAA4ADAAJwA7ACQAaQA9ACcAZgA5ADgA" ascii //weight: 2
        $x_2_2 = "AAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAIAAtAFUA" ascii //weight: 2
        $x_2_3 = "ILoveHF" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

