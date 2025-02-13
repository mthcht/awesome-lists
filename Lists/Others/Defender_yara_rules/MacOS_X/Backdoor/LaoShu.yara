rule Backdoor_MacOS_X_LaoShu_A_2147685132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/LaoShu.A"
        threat_id = "2147685132"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "LaoShu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "HtYGE4fFRj4DMt9S9V/8G" ascii //weight: 2
        $x_2_2 = "_msgSendSuper2" ascii //weight: 2
        $x_2_3 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 61 74 74 61 63 68 6d 65 6e 74 3b 20 6e 61 6d 65 3d 22 [0-16] 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 40}  //weight: 2, accuracy: Low
        $x_2_4 = {63 79 63 3a 3a [0-5] 79 63 79 3a [0-5] 65 6e 64 3a 6b 65 79 3a}  //weight: 2, accuracy: Low
        $x_2_5 = {2f 75 73 72 2f 62 69 6e 2f 7a 69 70 00 2d 73 00 32 35 6d 00 2d 72 00 61 00 25 40 25 40 00 2e 7a 69 70}  //weight: 2, accuracy: High
        $x_2_6 = "yang/lastupdateuploader" ascii //weight: 2
        $x_2_7 = {77 6f 72 74 00 65 71 6f 78 00 62 6f 76 78 00 63 78 78}  //weight: 2, accuracy: High
        $x_2_8 = "com.andrew.utility" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

