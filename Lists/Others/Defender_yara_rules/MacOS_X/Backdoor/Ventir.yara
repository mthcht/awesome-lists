rule Backdoor_MacOS_X_Ventir_A_2147689598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Ventir.A"
        threat_id = "2147689598"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Ventir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 61 72 67 65 74 55 52 4c 3a 00 73 65 74 53 6f 75 72 63 65 55 52 4c 3a 00 73 65 74 4b 65 79 3a}  //weight: 1, accuracy: High
        $x_1_2 = "killall -9 reweb" ascii //weight: 1
        $x_1_3 = "SELECT * FROM config WHERE id=1" ascii //weight: 1
        $x_1_4 = "getconfig" ascii //weight: 1
        $x_1_5 = {00 25 40 2f 75 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_6 = "HOOK START!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

