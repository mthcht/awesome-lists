rule Backdoor_Win32_Darkddoser_B_2147667401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Darkddoser.B"
        threat_id = "2147667401"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkddoser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 08 2a 0a 75 ?? 53 8b 58 fc 2b 5a fc 53 83 d1 ff 21 d9 2b 48 fc 29 c8 29 ca 8b 1c 01 33 1c 11}  //weight: 5, accuracy: Low
        $x_1_2 = "STATUS|Execut" ascii //weight: 1
        $x_1_3 = "STATUS|Idle" ascii //weight: 1
        $x_1_4 = "STATUS|Download" ascii //weight: 1
        $x_1_5 = "STATUS|Flood" ascii //weight: 1
        $x_1_6 = "darkddoser" ascii //weight: 1
        $x_1_7 = "STOPFLOOD" ascii //weight: 1
        $x_1_8 = {73 76 63 68 6f 73 74 2e 65 78 65 [0-16] 44 61 52 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Darkddoser_A_2147667402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Darkddoser.A"
        threat_id = "2147667402"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkddoser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "HTTP Flood Active" ascii //weight: 2
        $x_1_2 = {ba 01 20 00 00 e8 ?? ?? ff ff 6a 00 68 01 20 00 00 57 8b 43 04 50 e8 ?? ?? ff ff ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = {66 c7 43 08 02 00 0f b7 07 50 e8 ?? ?? ff ff 66 89 43 0a 8d 4d fc}  //weight: 1, accuracy: Low
        $x_1_4 = "darkddoser" ascii //weight: 1
        $x_1_5 = "SYN Flood Active" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Darkddoser_D_2147667413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Darkddoser.D"
        threat_id = "2147667413"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkddoser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ":\\autorun.inf" ascii //weight: 5
        $x_5_2 = "ddoser" ascii //weight: 5
        $x_1_3 = "ADDNEW|Idle" ascii //weight: 1
        $x_1_4 = "DOWNCOMP|" ascii //weight: 1
        $x_1_5 = "SYNStart" ascii //weight: 1
        $x_1_6 = "USB|Infected Drive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Darkddoser_E_2147681695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Darkddoser.E"
        threat_id = "2147681695"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkddoser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 44 50 7c [0-25] 53 59 4e 7c [0-16] 48 54 54 50 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "(*.exe)|*.exe|com (*.com)|*.com|pif (*.pif)|*.pif" ascii //weight: 1
        $x_1_3 = "darkddoser" ascii //weight: 1
        $x_5_4 = {0f b6 08 2a 0a 75 ?? 53 8b 58 fc 2b 5a fc 53 83 d1 ff 21 d9 2b 48 fc 29 c8 29 ca 8b 1c 01 33 1c 11}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

