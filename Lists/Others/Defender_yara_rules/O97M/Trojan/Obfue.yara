rule Trojan_O97M_Obfue_RPWD_2147819543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfue.RPWD!MTB"
        threat_id = "2147819543"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfue"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "().Exec \"Powe\" + gm2 + gm3 + gm4" ascii //weight: 1
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-7] 29}  //weight: 1, accuracy: Low
        $x_1_3 = "xOut = xOut & VBA.Mid(xValue, i, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

