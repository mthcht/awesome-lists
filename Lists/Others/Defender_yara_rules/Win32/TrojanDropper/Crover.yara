rule TrojanDropper_Win32_Crover_2147599906_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Crover"
        threat_id = "2147599906"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Crover"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2" wide //weight: 1
        $x_1_2 = "Select * from Win32_BaseBoard" wide //weight: 1
        $x_1_3 = "C:\\InsideTm" wide //weight: 1
        $x_1_4 = "Sorry But This Cant Be SandBoxed" wide //weight: 1
        $x_1_5 = "VmWare Detected" wide //weight: 1
        $x_1_6 = "Anti-Fortress Grand Sandbox Detected" wide //weight: 1
        $x_1_7 = "Sorry But This Cant Be Anubised" wide //weight: 1
        $x_5_8 = "Security_Hackers_Stub" ascii //weight: 5
        $x_5_9 = "clsFileBinder" ascii //weight: 5
        $x_5_10 = "H0000SecurityHackers" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

