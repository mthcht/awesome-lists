rule Trojan_O97M_Powdoclau_A_2147725822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Powdoclau.A"
        threat_id = "2147725822"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdoclau"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {46 73 6f 2e 43 72 45 61 74 45 74 45 58 54 66 49 6c 45 28 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 [0-64] 2e 77 73 66}  //weight: 10, accuracy: Low
        $x_1_2 = "377312201708161011591678891211899134718141815539111937189811" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

