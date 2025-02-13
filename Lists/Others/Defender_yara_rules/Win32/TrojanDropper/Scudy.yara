rule TrojanDropper_Win32_Scudy_A_2147629885_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Scudy.A"
        threat_id = "2147629885"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Scudy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 07 32 18 83 c0 04 88 5c 28 fc 8a 1c 0a 32 58 fd 83 c1 04 88 59 fc 8a 58 fe 32 5e ff 83 c6 04 88 59 fd 8a 58 ff 32 5e fc 88 59 fe}  //weight: 1, accuracy: High
        $x_1_2 = "EnumResNameProc::FindResource" ascii //weight: 1
        $x_1_3 = "ShowSuperHidden" ascii //weight: 1
        $x_1_4 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

