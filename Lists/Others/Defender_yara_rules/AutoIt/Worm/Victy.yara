rule Worm_AutoIt_Victy_A_2147692738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:AutoIt/Victy.A"
        threat_id = "2147692738"
        type = "Worm"
        platform = "AutoIt: AutoIT scripts"
        family = "Victy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FILECOPY ( @USERPROFILEDIR & \"\\autorun.inf\" , $VOLUME & \"\\autorun.inf\" , 1 )" ascii //weight: 1
        $x_1_2 = {49 46 20 46 49 4c 45 47 45 54 53 49 5a 45 20 28 20 24 53 55 42 44 49 52 20 26 20 22 2e 65 78 65 22 20 29 20 3c 3e 20 24 49 4e 49 54 53 49 5a 45 20 54 48 45 4e 20 46 49 4c 45 43 4f 50 59 20 28 20 40 53 54 41 52 54 55 50 44 49 52 20 26 20 22 5c [0-10] 2e 65 78 65 22 20 2c 20 24 53 55 42 44 49 52 20 26 20 22 2e 65 78 65 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 45 47 57 52 49 54 45 20 28 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2c 20 22 4b 49 4c 4c 22 20 2c 20 22 52 45 47 5f 53 5a 22 20 2c 20 40 53 54 41 52 54 55 50 44 49 52 20 26 20 22 5c [0-10] 2e 65 78 65 22 20 29}  //weight: 1, accuracy: Low
        $x_1_4 = "IF $SLOT.InterfaceType = \"USB\" THEN SPREAD ( $MAPVOL , $SLOT.PNPdeviceID )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

