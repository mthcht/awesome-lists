rule Backdoor_Win32_Bulknet_MA_2147829199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bulknet.MA!MTB"
        threat_id = "2147829199"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulknet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 37 88 06 ff d5 8a cb 80 e9 40 30 0e 43 46 81 fb ff 03 00 00 72}  //weight: 1, accuracy: High
        $x_1_2 = {53 53 6a 03 53 6a 01 68 00 00 00 80 8d 4c 24 2c 51 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "UnmapViewOfFile" ascii //weight: 1
        $x_1_4 = "InternetConnectW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

