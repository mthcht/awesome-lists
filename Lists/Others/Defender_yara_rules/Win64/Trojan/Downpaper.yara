rule Trojan_Win64_Downpaper_GVA_2147972348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Downpaper.GVA!MTB"
        threat_id = "2147972348"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Downpaper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sami.exe.config" ascii //weight: 1
        $x_1_2 = "rundll32.exe %s,InstallHinfSection %s 128 %s" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_4 = "Command.com /c %s" ascii //weight: 1
        $x_1_5 = "System\\CurrentControlSet\\Control\\Session Manager\\FileRenameOperations" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths" ascii //weight: 1
        $x_1_7 = "DelNodeRunDLL32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

