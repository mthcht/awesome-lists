rule Backdoor_Win32_Dalbot_2147648246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dalbot"
        threat_id = "2147648246"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Y21kLmV4ZQ==" ascii //weight: 1
        $x_1_2 = "YzpcXHdpbmRvd3NcXHN5c3RlbTMyXFxjbWQuZXhl" ascii //weight: 1
        $x_1_3 = "Leave SendCommandReq!" ascii //weight: 1
        $x_1_4 = {72 65 71 70 61 74 68 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 46 49 4c 45 43 4f 4e 54 45 4e 54 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = "clientpath" wide //weight: 1
        $x_1_7 = "reqfilepath" wide //weight: 1
        $x_1_8 = "Q3JlYXRlUHJvY2Vzc0E=" ascii //weight: 1
        $x_1_9 = "clientkey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

