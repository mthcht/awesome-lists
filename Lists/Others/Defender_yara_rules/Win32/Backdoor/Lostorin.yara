rule Backdoor_Win32_Lostorin_A_2147611301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lostorin.A"
        threat_id = "2147611301"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lostorin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 96 00 00 00 73 04 6a 64 ff d3 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {75 38 81 7e 04 02 12 00 00 74 22 8b 4e 08}  //weight: 1, accuracy: High
        $x_1_3 = {c7 03 78 56 34 12 c7 43 04 08 00 00 00 c7 43 08 14 00 00 00 c7 43 0c 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lostorin_B_2147630814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lostorin.B"
        threat_id = "2147630814"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lostorin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You Win!" ascii //weight: 1
        $x_1_2 = "Process Kill OK" ascii //weight: 1
        $x_1_3 = "key_log start" ascii //weight: 1
        $x_1_4 = "OpenUserDesktop is ok" ascii //weight: 1
        $x_1_5 = "key hook is ok" ascii //weight: 1
        $x_1_6 = "C:\\RECYCLER\\KEY-%d-%d-%d.LOG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

