rule Backdoor_Win32_Ripgof_B_2147619540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ripgof.B"
        threat_id = "2147619540"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ripgof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {65 64 5c 00 63 3a 5c 72 65 63 79 63 6c 00}  //weight: 10, accuracy: High
        $x_10_2 = "Listener reads Remote Routing Information Protocol (RIP) packets" ascii //weight: 10
        $x_10_3 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 10
        $x_10_4 = "ServiceDll" ascii //weight: 10
        $x_10_5 = "\\inf\\ip" ascii //weight: 10
        $x_1_6 = "\\niprp.dll" ascii //weight: 1
        $x_1_7 = "\\pwfsh.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

