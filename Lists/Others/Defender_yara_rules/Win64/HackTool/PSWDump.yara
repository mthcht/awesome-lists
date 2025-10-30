rule HackTool_Win64_PSWDump_MX_2147956415_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PSWDump.MX!MTB"
        threat_id = "2147956415"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PSWDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "65"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "ReflectiveLoader" ascii //weight: 50
        $x_5_2 = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" wide //weight: 5
        $x_5_3 = "Brave-Browser\\Application\\brave.exe" wide //weight: 5
        $x_5_4 = "Edge\\Application\\msedge.exe" wide //weight: 5
        $x_5_5 = ".\\pipe\\chrome_abe" wide //weight: 5
        $x_5_6 = "chrome_inject.exe" wide //weight: 5
        $x_5_7 = "Global\\ChromeDecryptWorkDoneEvent" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_PSWDump_MY_2147956416_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PSWDump.MY!MTB"
        threat_id = "2147956416"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PSWDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Direct Syscall-Based Reflective Hollowing" ascii //weight: 5
        $x_5_2 = "chrome_inject.exe" wide //weight: 5
        $x_5_3 = "ReflectiveLoader" ascii //weight: 5
        $x_5_4 = "Cookies" ascii //weight: 5
        $x_5_5 = "Passwords" ascii //weight: 5
        $x_5_6 = "Payments" ascii //weight: 5
        $x_5_7 = "Parsing payload PE headers for ReflectiveLoader" ascii //weight: 5
        $x_5_8 = "Loading and decrypting payload DLL" ascii //weight: 5
        $x_5_9 = "DLL_PIPE_COMPLETION_SIGNAL" ascii //weight: 5
        $x_5_10 = "chrome.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

