rule TrojanDropper_Win32_Redbinder_A_2147640351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Redbinder.A"
        threat_id = "2147640351"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Redbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "This is RedBindeR" ascii //weight: 5
        $x_3_2 = "RedBinder" ascii //weight: 3
        $x_2_3 = "C:\\Windows\\system.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

