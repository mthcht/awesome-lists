rule Trojan_O97M_Donota_B_2147740939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donota.B"
        threat_id = "2147740939"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donota"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sheet1.Anykey" ascii //weight: 1
        $x_1_2 = {55 73 65 72 46 6f 72 6d [0-4] 2e 4c 61 62 65 6c 35 5f 43 6c 69 63 6b}  //weight: 1, accuracy: Low
        $x_1_3 = "savetofile \"18.e\" & \"xe\", 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

