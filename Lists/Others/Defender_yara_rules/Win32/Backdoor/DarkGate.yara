rule Backdoor_Win32_DarkGate_FF_2147893677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkGate.FF!dha"
        threat_id = "2147893677"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\tmpp\\autoit3.exe c:\\tmpp\\test.au3" ascii //weight: 1
        $x_1_2 = "DebugConnectWide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

