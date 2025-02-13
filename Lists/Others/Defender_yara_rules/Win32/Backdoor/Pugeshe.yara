rule Backdoor_Win32_Pugeshe_2147708105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pugeshe!dha"
        threat_id = "2147708105"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pugeshe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Usage:  EXE Port Password" ascii //weight: 1
        $x_1_2 = "Connect Error %d." ascii //weight: 1
        $x_1_3 = "Get Last Error reports %d" ascii //weight: 1
        $x_1_4 = "Password is wrong!" ascii //weight: 1
        $x_1_5 = "Connected %s: %s" ascii //weight: 1
        $x_1_6 = "linsening %d..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

