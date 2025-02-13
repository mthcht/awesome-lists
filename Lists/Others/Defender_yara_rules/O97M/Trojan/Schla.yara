rule Trojan_O97M_Schla_A_2147730710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Schla.A!MTB"
        threat_id = "2147730710"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Schla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "= CreateObject(\"Schedule.Service\")" ascii //weight: 2
        $x_2_2 = "CallByName" ascii //weight: 2
        $x_1_3 = {2e 54 61 67 10 00 3d 20 [0-16] 2e 54 61 67}  //weight: 1, accuracy: Low
        $x_1_4 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 [0-16] 2e 4c 61 62 65 6c [0-2] 2e 54 61 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

