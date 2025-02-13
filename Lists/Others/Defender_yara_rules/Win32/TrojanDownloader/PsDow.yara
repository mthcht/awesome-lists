rule TrojanDownloader_Win32_PsDow_A_2147837686_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PsDow.A!MTB"
        threat_id = "2147837686"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gBTAHQAYQByAHQALQBTAGwAZQBlAHAAIAAtAFMAZQBjAG8AbgBkAHMAIAA2ADAA" ascii //weight: 2
        $x_2_2 = "ACAAQQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQA" ascii //weight: 2
        $x_2_3 = "AtAEUAeABjAGwAdQBzAGkAbwBuAFAAYQB0AGgAIABAACgAJABlAG4AdgA6AFUAcwBlAHIAUAByAG8A" ascii //weight: 2
        $x_2_4 = "ZgBpAGwAZQAsACQAZQBuAHYAOgBTAHkAcwB0AGUAbQBEAHIAaQB2AGUAKQ" ascii //weight: 2
        $x_2_5 = "AAtAEYAbwByAGMAZQA" ascii //weight: 2
        $x_2_6 = "AoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4" ascii //weight: 2
        $x_2_7 = "AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlAC" ascii //weight: 2
        $x_2_8 = "ALQBDAGgAaQBsAGQAUABhAHQAaAA" ascii //weight: 2
        $x_2_9 = "AAoAEoAbwBpAG4ALQBQAGEAdABoACAALQBQAGEAdABoACAAJABlAG4AdgA6AFQAZQBtAHAAI" ascii //weight: 2
        $x_2_10 = "AFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEYAaQBsAGUAUABhAHQAaAA" ascii //weight: 2
        $x_2_11 = "powershell" ascii //weight: 2
        $x_2_12 = "-EncodedCommand" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_PsDow_B_2147894235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PsDow.B!MTB"
        threat_id = "2147894235"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "New-Object System.Net.WebClient" ascii //weight: 2
        $x_2_2 = ".DownloadFile(" ascii //weight: 2
        $x_2_3 = "New-Object -com shell.application" ascii //weight: 2
        $x_2_4 = ".shellexecute(" ascii //weight: 2
        $x_2_5 = "powershell -ExecutionPolicy Bypass -F" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

