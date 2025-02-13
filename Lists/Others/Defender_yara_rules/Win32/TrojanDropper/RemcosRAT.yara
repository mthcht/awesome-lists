rule TrojanDropper_Win32_RemcosRAT_A_2147836960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/RemcosRAT.A!MTB"
        threat_id = "2147836960"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32" ascii //weight: 1
        $x_1_2 = "rundll32.exe %s,InstallHinfSection %s 128 %s" ascii //weight: 1
        $x_1_3 = "cmd /c cmd <" ascii //weight: 1
        $x_1_4 = ".htm & ping -n 5 localhost" ascii //weight: 1
        $x_1_5 = "Command.com /c %s" ascii //weight: 1
        $x_1_6 = "wextract_cleanup%d" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

