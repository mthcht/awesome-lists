rule Backdoor_Win32_RustyDoor_A_2147957210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RustyDoor.A!dha"
        threat_id = "2147957210"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RustyDoor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetMUITransfer" ascii //weight: 1
        $x_1_2 = {24 23 34 3a 32 14 52 19 10 03 01 18 24 2a 04 11 13 01 7f 18 04 4b 00 0b 0c}  //weight: 1, accuracy: High
        $x_1_3 = {16 01 15 53 09 16 56 19 43 03 0d 06 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

