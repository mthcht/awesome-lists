rule Trojan_Win32_ValleyRAT_EC_2147913492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.EC!MTB"
        threat_id = "2147913492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c6 83 e0 0f 8a 04 08 30 04 16 46 3b f3 72 f0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_PAHL_2147949159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.PAHL!MTB"
        threat_id = "2147949159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "monitor.bat" ascii //weight: 2
        $x_2_2 = "tasklist /FI \"IMAGENAME eq %ProcessName%\" | findstr /I \"%ProcessName%\" >nul" ascii //weight: 2
        $x_1_3 = "cmd.exe /B /c \"%s\"" ascii //weight: 1
        $x_1_4 = "monitor.pid" ascii //weight: 1
        $x_1_5 = "copy /Y \"%BackupProcessPath%\" \"%ProcessPath%\"" ascii //weight: 1
        $x_1_6 = "INVALID.aps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

