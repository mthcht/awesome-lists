rule Backdoor_MacOS_SysJoker_A_2147810208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/SysJoker.A"
        threat_id = "2147810208"
        type = "Backdoor"
        platform = "MacOS: "
        family = "SysJoker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/Library/LaunchAgents/com.apple.update.plist" ascii //weight: 2
        $x_2_2 = {2f 4c 69 62 72 61 72 79 2f 4d 61 63 4f 73 53 65 72 76 69 63 65 73 00 2f 4c 69 62 72 61 72 79 2f 53 79 73 74 65 6d 4e 65 74 77 6f 72 6b}  //weight: 2, accuracy: High
        $x_1_3 = "addToStatup" ascii //weight: 1
        $x_1_4 = "welcome to extenal app" ascii //weight: 1
        $x_1_5 = "OXgb77WNbU90vyUbZAucfzy0eF1HqtBNbkXiQ6SSbquuvFPUepqUEjUSQIDAQAB" ascii //weight: 1
        $x_1_6 = {2f 61 70 69 2f 61 74 74 61 63 68 00 2f 61 70 69 2f 72 65 71 2f 72 65 73 00 74 6f 6b 65 6e 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

