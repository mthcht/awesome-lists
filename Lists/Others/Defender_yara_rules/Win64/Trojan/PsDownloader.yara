rule Trojan_Win64_PsDownloader_CAMO_2147847643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PsDownloader.CAMO!MTB"
        threat_id = "2147847643"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PsDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cABvAHcAZQByAHMAaABlAGwAbAAgAC0ARQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdA" ascii //weight: 1
        $x_1_2 = "ByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxADAALgAyADoAOAAwAC8AcgBlAHYAXwBzAGgAZQBsAGwALgB0AHgAdAAnACkA" ascii //weight: 1
        $x_1_3 = "powershell -nop -exec bypass -w hidden -e" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\system32\\cmd.exe /c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

