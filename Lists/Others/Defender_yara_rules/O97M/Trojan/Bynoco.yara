rule Trojan_O97M_Bynoco_PA_2147731226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Bynoco.PA"
        threat_id = "2147731226"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bynoco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "formTag = crysler.Tag" ascii //weight: 1
        $x_1_2 = "= taskDefinition.Actions.Create(ate)" ascii //weight: 1
        $x_1_3 = {43 61 6c 6c 20 77 68 65 72 65 54 6f 2e 52 65 67 69 73 74 65 72 54 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 28 20 5f 0d 0a 20 20 20 20 22 53 68 63 65 64 75 6c 65 64 20 75 70 64 61 74 65 20 74 61 73 6b 22 2c 20 74 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 2c 20 36 2c 20 2c 20 2c 20 33 29}  //weight: 1, accuracy: High
        $x_1_4 = "Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

