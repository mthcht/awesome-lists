rule Virus_Linux_Rcrgood_A_2147689698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Linux/Rcrgood.gen!A"
        threat_id = "2147689698"
        type = "Virus"
        platform = "Linux: Linux platform"
        family = "Rcrgood"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 29 7f 45 4c 46 75 64 80 69 10 02 75 5e 83 c1 20 ff 49 14 75 f8 8b 41 28 f7 d8 80 e4 0f 66 3d}  //weight: 1, accuracy: High
        $x_1_2 = {81 29 7f 45 4c 46 75 69 80 69 10 02 75 63 81 c1 20 00 00 00 ff 49 14 75 f5 8b 41 28 f7 d8 80 e4 0f 66 3d}  //weight: 1, accuracy: High
        $x_1_3 = "[4096] virus coded by badCRC in 2003" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

