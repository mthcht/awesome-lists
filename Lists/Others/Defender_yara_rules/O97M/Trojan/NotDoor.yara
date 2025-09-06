rule Trojan_O97M_NotDoor_2147951615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/NotDoor"
        threat_id = "2147951615"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "NotDoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nothing" ascii //weight: 1
        $x_1_2 = "oQNfWDdmfdvnOnYQAuAG0AYQB0AHQAaQA0ADQANABAAHAAcgBvAHQAbwBuAC4AbQBlAA" ascii //weight: 1
        $x_1_3 = "Re: " ascii //weight: 1
        $x_1_4 = " :::1::: " ascii //weight: 1
        $x_1_5 = " :::2::: " ascii //weight: 1
        $x_1_6 = "_part_last" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

