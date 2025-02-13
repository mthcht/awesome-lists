rule Backdoor_MSIL_SpyNoon_2147755726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SpyNoon!MTB"
        threat_id = "2147755726"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EntryPoint" ascii //weight: 1
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_4 = "get_ExecutablePath" ascii //weight: 1
        $x_1_5 = "get_MachineName" ascii //weight: 1
        $x_1_6 = "get_CurrentDomain" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "Set WshShell = WScript.CreateObject(\"WScript.Shell\")" wide //weight: 1
        $x_1_9 = "WshShell.Run\"C:\\" wide //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_11 = "InstallUtil.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

