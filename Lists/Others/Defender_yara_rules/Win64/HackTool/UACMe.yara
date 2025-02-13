rule HackTool_Win64_UACMe_A_2147749989_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/UACMe.A!MSR"
        threat_id = "2147749989"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "UACMe"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UAC\\COMAutoApprovalList" wide //weight: 1
        $x_1_2 = "/run /tn \"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup\" /i" wide //weight: 1
        $x_1_3 = "UACMe main module" wide //weight: 1
        $x_1_4 = "UAC is now disabled" wide //weight: 1
        $x_1_5 = "You must reboot your computer for the changes to take effect." wide //weight: 1
        $x_1_6 = "_FubukiProc4" ascii //weight: 1
        $x_1_7 = "UACMe v 3.1.9.1905" wide //weight: 1
        $x_1_8 = "\\Software\\KureND" wide //weight: 1
        $x_1_9 = "ArisuTsuberuku" wide //weight: 1
        $x_1_10 = "AkagiCompletionEvent" wide //weight: 1
        $x_1_11 = "AkagiSharedSection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

