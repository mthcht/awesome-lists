rule Backdoor_Win32_IronTiger_A_2147729278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IronTiger.A!MTB"
        threat_id = "2147729278"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IronTiger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuckadmin" ascii //weight: 1
        $x_1_2 = "Welcome to door by ourselves!" ascii //weight: 1
        $x_1_3 = "Fw_DrvAnti" ascii //weight: 1
        $x_1_4 = "HdFw_Anti_sys" wide //weight: 1
        $x_1_5 = "runing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

