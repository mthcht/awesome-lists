rule Backdoor_Win32_Baceed_A_2147708988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Baceed.A!bit"
        threat_id = "2147708988"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Baceed"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\P\\7343893" ascii //weight: 1
        $x_1_2 = "\\Modules\\BaseCode\\MyIni.cpp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

