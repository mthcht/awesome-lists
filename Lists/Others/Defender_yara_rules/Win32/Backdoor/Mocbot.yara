rule Backdoor_Win32_Mocbot_2147571575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mocbot"
        threat_id = "2147571575"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mocbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {ba 80 11 40 00 b9}  //weight: 3, accuracy: High
        $x_3_2 = {00 00 e8 0f 00 00 00 ba}  //weight: 3, accuracy: High
        $x_2_3 = {42 e2 fa c2 08 00}  //weight: 2, accuracy: High
        $x_1_4 = {40 00 80 32}  //weight: 1, accuracy: High
        $x_5_5 = {33 c9 66 b9 6c 6c 51 68 33 32 2e 64 68 77 73 32 5f 54 ff d0 8b d8}  //weight: 5, accuracy: High
        $x_5_6 = {40 00 3d 99 01 00 00 75 24 6a 00 6a 00 68 01 02 00 00 ff 75 f8 ff 15}  //weight: 5, accuracy: High
        $x_5_7 = {88 45 e0 80 7d e0 30 74 11 80 7d e0 31 74 02 eb 0f c7 45 f4 01 00 00 00 eb 16}  //weight: 5, accuracy: High
        $x_4_8 = "%s\\ddbug\\dcpromo" ascii //weight: 4
        $x_4_9 = ".wallloan.com" ascii //weight: 4
        $x_4_10 = ".househot.com" ascii //weight: 4
        $x_3_11 = "[exec] :" ascii //weight: 3
        $x_3_12 = {50 6f 4e 47 20 25 2e 35 30 30 73 0d}  //weight: 3, accuracy: High
        $x_3_13 = "result in system instability" ascii //weight: 3
        $x_3_14 = "\\CurrentControlSet\\Control\\Lsa" ascii //weight: 3
        $x_3_15 = "*!admin@admin" ascii //weight: 3
        $x_2_16 = "_Oscar_" ascii //weight: 2
        $x_2_17 = "\\IPC$" ascii //weight: 2
        $x_1_18 = "\\BROWSER" ascii //weight: 1
        $x_1_19 = "\\PIPE\\" ascii //weight: 1
        $x_1_20 = "LANMAN 2.1" ascii //weight: 1
        $x_1_21 = "restrictanonymous" ascii //weight: 1
        $x_1_22 = "*PRIVMSG *" ascii //weight: 1
        $x_1_23 = "*ddos*" ascii //weight: 1
        $x_1_24 = "%.128s\\%.64s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

