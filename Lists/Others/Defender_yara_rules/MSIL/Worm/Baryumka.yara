rule Worm_MSIL_Baryumka_A_2147709646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Baryumka.A"
        threat_id = "2147709646"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Baryumka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6b 65 79 4c 6f 67 67 65 72 00 63 6f 6e 74 72 6f 6c 53 74 61 74 65}  //weight: 2, accuracy: High
        $x_2_2 = {75 70 6c 6f 61 64 46 69 6c 65 00 75 72 6c}  //weight: 2, accuracy: High
        $x_2_3 = "takeOverHost" ascii //weight: 2
        $x_2_4 = "infectCTD" ascii //weight: 2
        $x_1_5 = {61 64 64 54 6f 53 74 61 72 74 75 70 00 70 61 74 68}  //weight: 1, accuracy: High
        $x_1_6 = "createShotcutOnRemovable" ascii //weight: 1
        $x_4_7 = "kayumba.us.to,http://kayumbaamback.us.to" wide //weight: 4
        $x_2_8 = "/qwertyuiopqwertyuiop.net" wide //weight: 2
        $x_2_9 = "/asdfghjklasdfghjk.info" wide //weight: 2
        $x_2_10 = "/kayumbaforthelasttime.net" wide //weight: 2
        $x_1_11 = "\\upflder\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

