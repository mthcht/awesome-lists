rule Backdoor_MacOS_DevilRobber_A_2147815024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/DevilRobber.A!xp"
        threat_id = "2147815024"
        type = "Backdoor"
        platform = "MacOS: "
        family = "DevilRobber"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unzip binary.zip > /dev/null" ascii //weight: 1
        $x_1_2 = "d_status.cfg" ascii //weight: 1
        $x_1_3 = "./d_stop.sh" ascii //weight: 1
        $x_1_4 = "./p_start.sh" ascii //weight: 1
        $x_3_5 = {38 00 01 00 3d 60 80 80 39 20 00 00 7c 09 03 a6 61 6b 80 81 7c 49 49 d6 38 42 00 17 7c 02 58 16 54 00 c9 fe 7c 42 02 14 7c 43 49 ae 39 29 00 01 42 00 ff e4 38 60 00 00 4e 80 00 20}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

