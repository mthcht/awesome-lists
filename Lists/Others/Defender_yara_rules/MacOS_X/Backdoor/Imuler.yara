rule Backdoor_MacOS_X_Imuler_A_2147649887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Imuler.A"
        threat_id = "2147649887"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Imuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 fe 07 7e 11 8b 03 a3 c0 34 01 00 8b 43 04 a3 c4 34 01 00 eb 14}  //weight: 1, accuracy: High
        $x_1_2 = {f7 d0 21 c2 81 e2 80 80 80 80 74 e9 89 d0 c1 e8 10 f7 c2 80 80 00 00 0f 44 d0 8d 41 02 0f 45 c1 00 d2 83 d8 03 c7 00 2f 63 67 69 c7 40 04 2d 6d 61 63 c7 40 08 2f 32 77 6d}  //weight: 1, accuracy: High
        $x_1_3 = {8b 01 83 c1 04 8d 90 ff fe fe fe f7 d0 21 c2 81 e2 80 80 80 80 74 e9 89 d0 c1 e8 10 f7 c2 80 80 00 00 0f 44 d0 8d 41 02 0f 44 c8 00 d2 83 d9 03 81 e9 60 32 01 00}  //weight: 1, accuracy: High
        $x_1_4 = {89 c3 ba ab aa aa 2a f7 ea d1 fa 89 d9 c1 f9 1f 29 ca 8d 14 52 c1 e2 02 29 d3 8d 43 01 89 04 24 e8 7e 06 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_MacOS_X_Imuler_C_2147655173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Imuler.C"
        threat_id = "2147655173"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Imuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".confr" ascii //weight: 1
        $x_1_2 = "/tmp/.md" ascii //weight: 1
        $x_1_3 = "/tmp/.mdworker" ascii //weight: 1
        $x_1_4 = "/tmp/launch-IORF98" ascii //weight: 1
        $x_1_5 = "FileAgentApp" ascii //weight: 1
        $x_1_6 = "application:openTempFile:" ascii //weight: 1
        $x_1_7 = "application:openFileWithoutUI:" ascii //weight: 1
        $x_1_8 = "applicationWillHide:" ascii //weight: 1
        $x_1_9 = "TMP0M34" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_MacOS_X_Imuler_B_2147655211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Imuler.B"
        threat_id = "2147655211"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Imuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/tmp/xntaskz" ascii //weight: 1
        $x_1_2 = "%s:%s:%u:%f:%f" ascii //weight: 1
        $x_1_3 = "(server name) (machine id) (file name) (task id)" ascii //weight: 1
        $x_1_4 = "/cgi-mac/" ascii //weight: 1
        $x_1_5 = "/users/%s/xnocz1" ascii //weight: 1
        $x_1_6 = "/users/%s/library/.confback" ascii //weight: 1
        $x_1_7 = {c1 e8 10 f7 c2 80 80 00 00 0f 44 d0 [0-2] 8d 41 02 [0-2] 0f 45 c1 00 d2 [0-2] 83 d8 03 [0-2] 2f 63 67 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MacOS_X_Imuler_D_2147668083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Imuler.D"
        threat_id = "2147668083"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Imuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/tmp/launch-I" ascii //weight: 1
        $x_1_2 = "/bin/sh" ascii //weight: 1
        $x_1_3 = ".confr" ascii //weight: 1
        $x_2_4 = {46 49 4c 45 [0-5] 41 47 45 4e [0-5] 54 56 65 72}  //weight: 2, accuracy: Low
        $x_2_5 = {80 3a 2f 75 0a 83 f9 04 74 0b c6 42 01 00 41 48 4a 85 c0}  //weight: 2, accuracy: High
        $x_2_6 = {2f 80 00 2f 40 9e 00 14 2f 89 00 04 41 9e 00 14 99 62 00 01 39 29 00 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

