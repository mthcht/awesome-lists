rule VirTool_Win32_Gopurp_A_2147793877_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Gopurp.A"
        threat_id = "2147793877"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Gopurp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/GoPurple/" ascii //weight: 1
        $x_1_2 = "/helpers.FetchUrl" ascii //weight: 1
        $x_1_3 = "/sliverpkg.CreateProcess" ascii //weight: 1
        $x_1_4 = "/techniques.RunCreateRemoteThread" ascii //weight: 1
        $x_1_5 = "/techniques.RunSyscall.stkobj" ascii //weight: 1
        $x_1_6 = "/techniques.WriteShellcode" ascii //weight: 1
        $x_1_7 = "/techniques.EBAPCQueue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

