rule Backdoor_Win32_Loretsys_A_2147684755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Loretsys.A"
        threat_id = "2147684755"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Loretsys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 54 74 49 6e 47 73 [0-10] 72 75 73 73 69 61 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {41 50 54 52 41 20 20 20 20 20 20 20 25 73 [0-4] 54 72 61 6e 73 61 63 74 69 6f 6e 73 20 25 64}  //weight: 1, accuracy: Low
        $x_1_3 = ".DEFAULT\\XFS\\LOGICAL_SERVICES" ascii //weight: 1
        $x_1_4 = {00 72 74 6c 33 32 73 79 73 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {c1 ea 02 4a 83 fa 00 7c 16 8b 18 89 5d fc d1 45 fc 31 08 8b 4d fc 83 c0 04 4a 83 fa ff 75 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

