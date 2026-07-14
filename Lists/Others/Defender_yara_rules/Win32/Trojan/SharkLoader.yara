rule Trojan_Win32_SharkLoader_AMTB_2147973449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SharkLoader!AMTB"
        threat_id = "2147973449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SharkLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "E:\\2023\\FileBand\\Bin\\Banana.pdb" ascii //weight: 6
        $x_1_2 = "TrackMouseEvent" ascii //weight: 1
        $x_1_3 = "ResetEvent" ascii //weight: 1
        $x_1_4 = "CreateEventW" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "LockFile" ascii //weight: 1
        $x_1_7 = "SleepConditionVariableCS" ascii //weight: 1
        $x_1_8 = "ShellExecuteW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

