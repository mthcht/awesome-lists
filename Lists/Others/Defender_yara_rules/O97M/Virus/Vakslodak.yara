rule Virus_O97M_Vakslodak_2147806085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/Vakslodak.gen"
        threat_id = "2147806085"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Vakslodak"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "application.startuppath&\"/\"&\"office_.xls\"" ascii //weight: 10
        $x_6_2 = "codeforgotonowthen=int(rnd(" ascii //weight: 6
        $x_1_3 = "thenkill\"*.hlp\"" ascii //weight: 1
        $x_1_4 = "thenkill\"*.b*\"" ascii //weight: 1
        $x_1_5 = "thenkill\"*.c*\"" ascii //weight: 1
        $x_1_6 = "thenkill\"*.dll\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

