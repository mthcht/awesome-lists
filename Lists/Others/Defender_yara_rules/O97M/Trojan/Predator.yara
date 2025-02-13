rule Trojan_O97M_Predator_BB_2147748090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Predator.BB!MTB"
        threat_id = "2147748090"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VBA.CreateObject(\"MSXML2.DOMDocument\").CreateElement(\"dummy\")" ascii //weight: 1
        $x_1_2 = ".DataType = \"bin\" + \".base64\"" ascii //weight: 1
        $x_1_3 = {53 65 74 20 [0-10] 3d [0-10] 2e 43 6f 6e 6e 65 63 74 53 65 72 76 65 72 28 29 [0-32] 2e 53 65 63 75 72 69 74 79 5f 2e 49 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4c 65 76 65 6c 20 3d 20 35 36 20 5f [0-10] 2a 20 32 20 5f [0-10] 20 2d 20 31 30 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

