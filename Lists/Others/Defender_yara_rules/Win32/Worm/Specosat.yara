rule Worm_Win32_Specosat_A_2147649067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Specosat.A"
        threat_id = "2147649067"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Specosat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=HostsResponse&data=" ascii //weight: 1
        $x_1_2 = "=SystemInfoResponse&data=OS:" ascii //weight: 1
        $x_1_3 = {25 63 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 25 63 3a 5c 25}  //weight: 1, accuracy: High
        $x_1_4 = "=KeylogResponse&data=" ascii //weight: 1
        $x_1_5 = "schtasks /Create /RU \"%s\" /SC MINUTE /TR" ascii //weight: 1
        $x_1_6 = {3d 49 41 6d 41 6c 69 76 65 00}  //weight: 1, accuracy: High
        $x_1_7 = ".DownExecFile->" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

