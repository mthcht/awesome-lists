rule Trojan_O97M_Phish_ASM_2147838912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Phish.ASM!MTB"
        threat_id = "2147838912"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Phish"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$(iwr https://zevoday.blogspot.com/atom.xml -" ascii //weight: 1
        $x_1_2 = "als) | &('AJSAMSJWWUAU'.replace('AJSAMSJWWUAU','I'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

