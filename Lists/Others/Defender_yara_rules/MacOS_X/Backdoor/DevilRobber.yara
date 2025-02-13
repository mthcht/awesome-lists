rule Backdoor_MacOS_X_DevilRobber_A_2147651032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/DevilRobber.A"
        threat_id = "2147651032"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "DevilRobber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "screencapture -T 0 -x 1.png" ascii //weight: 1
        $x_1_2 = "/miner.sh %s %u %s %s" ascii //weight: 1
        $x_1_3 = "/polipo -c polipo.cfg" ascii //weight: 1
        $x_1_4 = {74 63 70 00 33 34 31 32 33 00 33 34 35 32 32 00 33 34 33 32 31}  //weight: 1, accuracy: High
        $x_1_5 = "%#.8x %#.8x %#.8x %#.8x %#.8x" ascii //weight: 1
        $x_3_6 = {be 81 80 80 80 53 31 db 89 d9 0f af cb 83 c1 17 89 c8 f7 e6 c1 ea 07 89 d0 c1 e0 08 29 d0 29 c1 88 0c 1f 43 81 fb 00 01 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MacOS_X_DevilRobber_B_2147651614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/DevilRobber.B"
        threat_id = "2147651614"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "DevilRobber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 63 70 00 33 34 31 32 33 00 33 34 33 32 31}  //weight: 1, accuracy: High
        $x_1_2 = "%#.8x %#.8x %#.8x %#.8x %#.8x" ascii //weight: 1
        $x_1_3 = "%#.8x_%#.8x_%#.8x.zip zip -r -X" ascii //weight: 1
        $x_1_4 = "d_status.cfg" ascii //weight: 1
        $x_1_5 = "./p_start.sh" ascii //weight: 1
        $x_3_6 = {be 81 80 80 80 53 31 db 89 d9 0f af cb 83 c1 17 89 c8 f7 e6 c1 ea 07 89 d0 c1 e0 08 29 d0 29 c1 88 0c 1f 43 81 fb 00 01 00 00}  //weight: 3, accuracy: High
        $x_3_7 = {89 e5 56 8b 75 08 53 8b 5d 0c 0f b6 04 16 84 c0 75 04 31 c0 eb 14 32 04 0a 88 04 13 42 81 fa 01 01 00 00 75 e5 b8 01 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

