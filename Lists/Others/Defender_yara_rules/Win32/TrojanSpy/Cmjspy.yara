rule TrojanSpy_Win32_Cmjspy_B_2147602658_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Cmjspy.B"
        threat_id = "2147602658"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cmjspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "GetIpAddrTable" ascii //weight: 10
        $x_10_2 = "PeekNamedPipe" ascii //weight: 10
        $x_4_3 = {6a 00 57 ff 76 10 e8 ?? ?? ?? ff 83 c4 2c 8d 45 08 6a 00 50 57 ff 76 10 ff 36 ff d3 83 c7 05}  //weight: 4, accuracy: Low
        $x_5_4 = {68 01 08 00 00 c6 45 fc 03 c7 06 ?? ?? ?? 10 89 7e 1c 89 7e 20 89 7e 30 89 7e 18 89 7e 14 c7 46 10 20 4e 00 00 c7 46 0c 00 08 00 00 e8 ?? ?? ?? 00 8b 1d ?? ?? ?? 10 c7 04 ?? ?? ?? ?? 10 57 6a 01 57 89 46 34 89 7e 58 89 7e 6c 89 7e 70 ff d3 50 89 46 04 ff 15}  //weight: 5, accuracy: Low
        $x_1_5 = "hlicense.vxd" ascii //weight: 1
        $x_1_6 = "sssdda334342.vxd" ascii //weight: 1
        $x_1_7 = "hlogo.2tx" ascii //weight: 1
        $x_1_8 = "file.2dir" ascii //weight: 1
        $x_1_9 = "reg.2ger" ascii //weight: 1
        $x_1_10 = {63 6d 64 2e 65 78 65 00 63 6f 6d 6d 61 6e 64 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

