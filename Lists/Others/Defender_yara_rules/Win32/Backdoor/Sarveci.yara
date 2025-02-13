rule Backdoor_Win32_Sarveci_A_2147629435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sarveci.A"
        threat_id = "2147629435"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sarveci"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Kav.key" ascii //weight: 1
        $x_1_2 = "NB_Server_Update" ascii //weight: 1
        $x_1_3 = "Jinshan_lj" ascii //weight: 1
        $x_1_4 = "ServiceAV3" ascii //weight: 1
        $x_10_5 = "[%d/%d/%d %d:%d:%d] (%s)" ascii //weight: 10
        $x_10_6 = "mICROSOFT\\nETWORK\\cONNECTIONS\\PBK\\RASPHONE.PBK" ascii //weight: 10
        $x_10_7 = "aPPLICATIONS\\IEXPLORE.EXE\\SHELL\\OPEN\\COMMAND" ascii //weight: 10
        $x_10_8 = "capGetDriverDescriptionA" ascii //weight: 10
        $x_10_9 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

