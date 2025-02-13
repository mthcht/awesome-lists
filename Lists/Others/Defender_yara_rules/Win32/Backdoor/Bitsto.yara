rule Backdoor_Win32_Bitsto_A_2147679641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bitsto.A"
        threat_id = "2147679641"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitsto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get user name error!" ascii //weight: 1
        $x_1_2 = {00 66 69 6c 65 75 70 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_3 = "machine type: maybe pc" ascii //weight: 1
        $x_1_4 = {52 75 6e 64 6c 6c 49 6e 73 74 61 6c 6c 41 00 52 75 6e 64 6c 6c 55 6e 69 6e 73 74 61 6c 6c 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {8a 0c 2a 8b c2 2b c6 8b fd 42 88 4c 18 ff 83 c9 ff 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

