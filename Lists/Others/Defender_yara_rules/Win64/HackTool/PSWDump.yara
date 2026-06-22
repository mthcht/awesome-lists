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
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "chromelevator.exe [options] <chrome|chrome-beta|edge|brave|all>" wide //weight: 10
        $x_5_2 = "Use chromelevator_" ascii //weight: 5
        $x_5_3 = "App-Bound Encryption Key" ascii //weight: 5
        $x_5_4 = "ExtractBrowserData" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_PSWDump_MX_2147956415_1
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
        $x_10_1 = "Direct Syscall-Based Reflective Hollowing" ascii //weight: 10
        $x_5_2 = "by @xaitax" ascii //weight: 5
        $x_5_3 = "SOFTWARE\\Clients\\StartMenuInternet\\Google Chrome\\shell" wide //weight: 5
        $x_10_4 = "Chromelevator" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_PSWDump_MY_2147956416_1
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

rule HackTool_Win64_PSWDump_GMX_2147967873_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PSWDump.GMX!MTB"
        threat_id = "2147967873"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PSWDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getChromiumProfiles" ascii //weight: 1
        $x_1_2 = "killNonHiddenChrome" ascii //weight: 1
        $x_1_3 = "ChromeCookie" ascii //weight: 1
        $x_1_4 = "main.startCookieSyncLoop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_PSWDump_PA_2147969798_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PSWDump.PA!MTB"
        threat_id = "2147969798"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PSWDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Avast Secure Browser\\shell\\open\\command" ascii //weight: 1
        $x_1_2 = "Bootstrap entry point resolved" ascii //weight: 1
        $x_1_3 = "Payload decrypted " ascii //weight: 1
        $x_1_4 = "Solution: Use chromelevator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_PSWDump_PMX_2147970420_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PSWDump.PMX!MTB"
        threat_id = "2147970420"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PSWDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "[+] No running processes found" ascii //weight: 5
        $x_5_2 = "Creating suspended process:" ascii //weight: 5
        $x_5_3 = "[+] Process created (PID:" ascii //weight: 5
        $x_5_4 = "[+] IPC pipe established:" ascii //weight: 5
        $x_5_5 = "[+] Payload connected" ascii //weight: 5
        $x_30_6 = "google\\chrome" wide //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_PSWDump_YMX_2147970647_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PSWDump.YMX!MTB"
        threat_id = "2147970647"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PSWDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[options] <chrome|chrome-beta|edge|" wide //weight: 10
        $x_5_2 = "Extract browser fingerprint" wide //weight: 5
        $x_5_3 = "Kill all browser processes before extraction" wide //weight: 5
        $x_5_4 = "--output-path" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_PSWDump_SX_2147971319_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PSWDump.SX!MTB"
        threat_id = "2147971319"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PSWDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Usage: chromelevator.exe [options]" ascii //weight: 50
        $x_20_2 = "\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Avast Secure Browser\\shell\\open\\command" ascii //weight: 20
        $x_15_3 = "Direct Syscall-Based Reflective Hollowing" ascii //weight: 15
        $x_15_4 = "Awaiting payload connection..." ascii //weight: 15
        $x_10_5 = "Injector" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

