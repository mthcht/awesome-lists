rule Trojan_Win32_Prockill_GA_2147773590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prockill.GA!MTB"
        threat_id = "2147773590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prockill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Killer" ascii //weight: 1
        $x_1_2 = "GetProcesses" ascii //weight: 1
        $x_1_3 = "taskmgr" ascii //weight: 1
        $x_1_4 = "regedit" ascii //weight: 1
        $x_1_5 = "wireshark" ascii //weight: 1
        $x_1_6 = "vmware" ascii //weight: 1
        $x_1_7 = "ollydbg" ascii //weight: 1
        $x_1_8 = "virtualbox" ascii //weight: 1
        $x_1_9 = "hijackthis" ascii //weight: 1
        $x_1_10 = "anubis" ascii //weight: 1
        $x_1_11 = "joebox" ascii //weight: 1
        $x_1_12 = "keyscrambler" ascii //weight: 1
        $x_1_13 = "msconfig" ascii //weight: 1
        $x_1_14 = "panda" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

