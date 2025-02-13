rule TrojanDownloader_Win32_BHO_A_2147610120_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BHO.A"
        threat_id = "2147610120"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 16 30 c2 d1 ea 73 02 31 fa 41 80 e1 07 75 f4 c1 e8 08 31 d0 46 80 3e 00 75}  //weight: 10, accuracy: High
        $x_10_2 = "00EBB3B3-DEAD-4440-B1F8-B09DDDB89EF3" ascii //weight: 10
        $x_10_3 = "ExitWindowsEx" ascii //weight: 10
        $x_10_4 = "DllRegisterServer" ascii //weight: 10
        $x_10_5 = "SeShutdownPrivilege" ascii //weight: 10
        $x_1_6 = "kav2" ascii //weight: 1
        $x_1_7 = "inject" ascii //weight: 1
        $x_1_8 = "dnsmask" ascii //weight: 1
        $x_1_9 = "PostDel" ascii //weight: 1
        $x_1_10 = "password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

