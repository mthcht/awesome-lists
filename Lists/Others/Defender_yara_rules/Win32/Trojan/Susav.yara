rule Trojan_Win32_Susav_A_2147625244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Susav.A"
        threat_id = "2147625244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Susav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EnumWindows" ascii //weight: 1
        $x_1_2 = "GetClassNameA" ascii //weight: 1
        $x_1_3 = {8b 85 c0 fe ff ff 3d 41 56 50 2e 75 02}  //weight: 1, accuracy: High
        $x_1_4 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

