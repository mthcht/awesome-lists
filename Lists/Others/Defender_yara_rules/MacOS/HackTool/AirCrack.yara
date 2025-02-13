rule HackTool_MacOS_AirCrack_C_2147748054_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/AirCrack.C!MTB"
        threat_id = "2147748054"
        type = "HackTool"
        platform = "MacOS: "
        family = "AirCrack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Aircrack-ng" ascii //weight: 1
        $x_1_2 = "www.aircrack-ng.org" ascii //weight: 1
        $x_1_3 = "try the experimental bruteforce attacks" ascii //weight: 1
        $x_1_4 = "PTW_newattackstate" ascii //weight: 1
        $x_1_5 = "Quitting aircrack-ng" ascii //weight: 1
        $x_1_6 = "Attack failed. Possible reasons:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_MacOS_AirCrack_A_2147816675_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/AirCrack.A!xp"
        threat_id = "2147816675"
        type = "HackTool"
        platform = "MacOS: "
        family = "AirCrack"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Aircrack-ng" ascii //weight: 1
        $x_1_2 = {64 6f 20 73 63 72 69 70 74 [0-16] 2d 61 20 25 6c 75 20 2d 62 20 25 40 20 2f 70 72 69 76 61 74 65 2f 74 6d 70 2f 61 69 72 70 6f 72 74 53 6e 69 66 66 2a 2e 63 61 70}  //weight: 1, accuracy: Low
        $x_1_3 = "isKorekAttack" ascii //weight: 1
        $x_1_4 = "startCaptur" ascii //weight: 1
        $x_1_5 = "startCrack" ascii //weight: 1
        $x_1_6 = "setKorekAttack:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

