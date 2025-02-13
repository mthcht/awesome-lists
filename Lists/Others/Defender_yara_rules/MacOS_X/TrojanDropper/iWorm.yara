rule TrojanDropper_MacOS_X_iWorm_A_2147689386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MacOS_X/iWorm.A"
        threat_id = "2147689386"
        type = "TrojanDropper"
        platform = "MacOS_X: "
        family = "iWorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<key>RunAtLoad</key>" ascii //weight: 1
        $x_1_2 = {2f 4c 69 62 72 61 72 79 2f 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 75 70 70 6f 72 74 2f 4a 61 76 61 57 00 4a 61 76 61 57}  //weight: 1, accuracy: High
        $x_1_3 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 44 61 65 6d 6f 6e 73 2f [0-16] 63 6f 6d 2e 4a 61 76 61 57 [0-16] 77 62 [0-16] 2e 70 6c 69 73 74 [0-16] 6c 61 75 6e 63 68 63 74 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {6c 61 75 6e 63 68 63 74 6c [0-5] 6c 6f 61 64 [0-5] 6c 61 75 6e 63 68 63 74 6c [0-5] 73 74 61 72 74}  //weight: 1, accuracy: Low
        $x_1_5 = {ce fa ed fe 07 00 00 00 03 00 00 00 02 00 00 00 05 00 00 00 b8 01}  //weight: 1, accuracy: High
        $x_1_6 = "UPX!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

