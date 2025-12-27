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

rule Trojan_Win32_ValleyRAT_GBVL_2147950691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.GBVL!MTB"
        threat_id = "2147950691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 01 89 85 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? ?? 73 ?? 8b 8d ?? ?? ?? ?? 0f be 54 0d ?? 81 f2 91 00 00 00 8b 85 ?? ?? ?? ?? 88 54 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_NW_2147958155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.NW!MTB"
        threat_id = "2147958155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 07 47 99 f7 f9 8b 46 08 8b 4d 10 80 c2 36 89 7d 08 32 14 08 88 14 01 b8 64 1d 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_AHB_2147959548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.AHB!MTB"
        threat_id = "2147959548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "mzy.dat" ascii //weight: 10
        $x_20_2 = "OpeeProcdssaoken" ascii //weight: 20
        $x_30_3 = {f7 f1 0f b7 1c 55 ?? ?? ?? ?? e8 ?? ?? ?? ?? 4f 75 ?? 8b c6 8b 4d f4}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

