rule Backdoor_Win32_Pingback_STA_2147780556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pingback.STA"
        threat_id = "2147780556"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pingback"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\TCPBDSV2.pdb" ascii //weight: 1
        $x_1_2 = "openfile on remote computers success" ascii //weight: 1
        $x_1_3 = {73 68 65 6c 6c [0-10] 64 69 72 20}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 45 4e 44 [0-10] 65 78 65 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 72 65 61 74 65 46 69 6c 65 [0-10] 50 65 65 6b 4e 61 6d 65 64 50 69 70 [0-10] 57 72 69 74 65 46 69 6c 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

