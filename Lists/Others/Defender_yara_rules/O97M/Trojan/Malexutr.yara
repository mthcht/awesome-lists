rule Trojan_O97M_Malexutr_SA_2147760826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Malexutr.SA!MTB"
        threat_id = "2147760826"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malexutr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 3d 20 22 70 22 20 2b 20 [0-8] 6f [0-8] 77 [0-8] 45 [0-8] 72 [0-8] 73 [0-8] 68 [0-8] 65 [0-8] 6c [0-8] 6c}  //weight: 5, accuracy: Low
        $x_1_2 = " = StrReverse(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

