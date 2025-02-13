rule Backdoor_Win32_Fsit_A_2147601234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fsit.A"
        threat_id = "2147601234"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "command.com" ascii //weight: 1
        $x_1_3 = "fshit.selfip.com/~fsock1/god.php" ascii //weight: 1
        $x_1_4 = ".php?pip=" ascii //weight: 1
        $x_1_5 = "CreateMutexA" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "InternetCloseHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

