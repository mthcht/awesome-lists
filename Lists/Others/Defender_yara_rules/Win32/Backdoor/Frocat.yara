rule Backdoor_Win32_Frocat_A_2147797319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Frocat.A!MTB"
        threat_id = "2147797319"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Frocat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(*API).Shred" ascii //weight: 1
        $x_1_2 = "(*API).Gomap" ascii //weight: 1
        $x_1_3 = "(*API).Speedtest" ascii //weight: 1
        $x_1_4 = "(*API).Screen" ascii //weight: 1
        $x_1_5 = "(*API).Reconnect" ascii //weight: 1
        $x_1_6 = "(*API).NewHostname" ascii //weight: 1
        $x_1_7 = "(*API).RunCmd" ascii //weight: 1
        $x_1_8 = "(*API).SendFile" ascii //weight: 1
        $x_1_9 = "(*API).RecvFile" ascii //weight: 1
        $x_1_10 = "(*API).GetHardware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

