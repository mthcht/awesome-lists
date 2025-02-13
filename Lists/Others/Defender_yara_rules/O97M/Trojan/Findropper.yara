rule Trojan_O97M_Findropper_G_2147735732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Findropper.G"
        threat_id = "2147735732"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Findropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "stojlomn & cahy & ifewa" ascii //weight: 2
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 28 55 73 65 72 46 6f 72 6d 31 2e [0-10] 2e 43 61 70 74 69 6f 6e 2c 20 22 23 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "MsgBox (\"Decryption error\")" ascii //weight: 1
        $x_1_4 = {4f 70 65 6e 20 [0-10] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 34 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

