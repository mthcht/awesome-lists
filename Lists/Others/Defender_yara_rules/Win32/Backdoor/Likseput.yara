rule Backdoor_Win32_Likseput_B_2147633549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Likseput.B"
        threat_id = "2147633549"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Likseput"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d0 f8 24 7f 42 3b d7 88 01 72 e7}  //weight: 2, accuracy: High
        $x_2_2 = {d0 e9 88 4c 05 88 40 83 f8 32 7c f0}  //weight: 2, accuracy: High
        $x_2_3 = {6a 23 50 ff d6 8b d8 59 85 db 59 0f 84 ?? ?? 00 00 6a 2e 53 ff d6 59 85 c0 59 0f 84 ?? ?? 00 00 80 20 00}  //weight: 2, accuracy: Low
        $x_2_4 = {3c 23 75 05 c6 01 3a eb 1d 33 d2 38 44 15 bc 74 06}  //weight: 2, accuracy: High
        $x_2_5 = {39 6e 24 74 0c bb 00 31 80 84 b8 bb 01 00 00 eb 08 6a 50 bb 00 01 00 84 58}  //weight: 2, accuracy: High
        $x_1_6 = "%d.%d %02d:%02d %s\\%s" ascii //weight: 1
        $x_1_7 = "list </p|/s|/d>" ascii //weight: 1
        $x_1_8 = "kill </p|/s> <pid|ServiceName>" ascii //weight: 1
        $x_1_9 = "start </p|/s> <filename|ServiceName>" ascii //weight: 1
        $x_1_10 = "getf/putf FileName <N>" ascii //weight: 1
        $x_1_11 = "Shell started successfully!" ascii //weight: 1
        $x_1_12 = "Volume on this computer:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Likseput_D_2147654675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Likseput.D"
        threat_id = "2147654675"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Likseput"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 06 d0 fa 80 e2 7f 41 88 10 40 3b 4d fc 72}  //weight: 1, accuracy: High
        $x_1_2 = {80 f1 46 d0 e9 88 4c 05 e0 40 83 f8 18}  //weight: 1, accuracy: High
        $x_1_3 = {6b 69 6c 6c 00 00 00 00 67 65 74 66 00 00 00 00 70 75 74 66 00 00 00 00 73 74 61 72 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

