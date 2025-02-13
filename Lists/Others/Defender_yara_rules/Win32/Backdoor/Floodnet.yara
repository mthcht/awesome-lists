rule Backdoor_Win32_Floodnet_C_2147646171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Floodnet.C"
        threat_id = "2147646171"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Floodnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 30 05 8a 08 88 0c 02 40 4e 75 f4}  //weight: 2, accuracy: High
        $x_1_2 = {c6 85 d5 fc ff ff 59 c6 85 d6 fc ff ff 53 c6 85 d7 fc ff ff 54 c6 85 d8 fc ff ff 45 c6 85 d9 fc ff ff 4d}  //weight: 1, accuracy: High
        $x_1_3 = {8d 04 40 33 d2 f7 74 24 04 8b c2}  //weight: 1, accuracy: High
        $x_1_4 = "in UdpPackFlood()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

