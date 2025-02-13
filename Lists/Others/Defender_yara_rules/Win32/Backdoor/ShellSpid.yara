rule Backdoor_Win32_ShellSpid_A_2147783189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ShellSpid.A!dha"
        threat_id = "2147783189"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellSpid"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "    /\\  |  /\\" ascii //weight: 1
        $x_1_2 = "    //\\. .//\\" ascii //weight: 1
        $x_1_3 = "    //\\ . //\\" ascii //weight: 1
        $x_1_4 = "    /  ( )/  \\" ascii //weight: 1
        $x_1_5 = "Welcome To Spider Shell!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

