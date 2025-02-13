rule Backdoor_Win32_ScarCruft_A_2147712575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ScarCruft.A!dha"
        threat_id = "2147712575"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ScarCruft"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Tencent\\QQPCMgr" ascii //weight: 1
        $x_1_2 = {6f 70 65 6e 66 61 69 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 65 6d 66 61 69 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 6c 6c 6f 63 66 61 69 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 55 43 43 00}  //weight: 1, accuracy: High
        $x_1_6 = {46 61 69 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

