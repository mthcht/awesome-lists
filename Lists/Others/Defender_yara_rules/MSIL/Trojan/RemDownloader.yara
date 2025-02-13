rule Trojan_MSIL_RemDownloader_2147771822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemDownloader!MTB"
        threat_id = "2147771822"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" wide //weight: 1
        $x_1_2 = "Add-MpPreference -ExclusionPath \"{0}\" -Force" wide //weight: 1
        $x_1_3 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" wide //weight: 1
        $x_1_4 = "Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon" wide //weight: 1
        $x_1_5 = "kernel32" wide //weight: 1
        $x_1_6 = "Wow64GetThreadContext" wide //weight: 1
        $x_1_7 = "GetThreadContext" wide //weight: 1
        $x_1_8 = "VirtualAllocEx" wide //weight: 1
        $x_1_9 = "WriteProcessMemory" wide //weight: 1
        $x_1_10 = "ReadProcessMemory" wide //weight: 1
        $x_1_11 = "ZwUnmapViewOfSection" wide //weight: 1
        $x_1_12 = "CreateProcessA" wide //weight: 1
        $x_1_13 = "ResumeThread" wide //weight: 1
        $x_1_14 = "Wow64SetThreadContext" wide //weight: 1
        $x_1_15 = "SetThreadContext" wide //weight: 1
        $x_1_16 = "trump2020" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

