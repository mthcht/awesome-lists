rule Trojan_O97M_Dotraj_T_2147759477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Dotraj.T!MTB"
        threat_id = "2147759477"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 73 70 61 67 22 20 26 20 22 2e 6a 22 20 26 20 [0-36] 20 26 20 22 73 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = "= CallByName(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Dotraj_U_2147760539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Dotraj.U!MTB"
        threat_id = "2147760539"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 69 6d 20 [0-16] 20 41 73 20 49 6e 74 65 67 65 72 02 00 00 20 3d 20 02 00 02 00 44 6f 20 57 68 69 6c 65 20 00 20 3c 20 02 00 20 2b 20 02 00 02 00 00 20 3d 20 00 20 2b 20 02 00 3a 20 44 6f 45 76 65 6e 74 73 02 00 4c 6f 6f 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Dotraj_V_2147763609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Dotraj.V!MTB"
        threat_id = "2147763609"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(\"TEMP\")" ascii //weight: 1
        $x_1_2 = "& \"\\\" & \"rsrs.exe\", vbHide" ascii //weight: 1
        $x_1_3 = "\"http://ge.tt/api" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

