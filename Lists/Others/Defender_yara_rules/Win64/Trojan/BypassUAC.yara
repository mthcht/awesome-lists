rule Trojan_Win64_BypassUAC_NE_2147920713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.NE!MTB"
        threat_id = "2147920713"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "System\\CurrentControlSet\\Control\\Nls\\Calendars\\Japanese\\Era" ascii //weight: 2
        $x_2_2 = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.ex" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Ru" ascii //weight: 2
        $x_1_4 = "C:\\windows\\tem" ascii //weight: 1
        $x_1_5 = "$disable uac" ascii //weight: 1
        $x_1_6 = "$disable regedit" ascii //weight: 1
        $x_1_7 = "hentai" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_NE_2147920713_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.NE!MTB"
        threat_id = "2147920713"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 73 00 6f 00 75 00 72 00 63 00 65 00 5c 00 72 00 65 00 70 00 6f 00 73 00 5c 00 [0-80] 5c 00 78 00 36 00 34 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-80] 2e 00 70 00 64 00 62 00}  //weight: 3, accuracy: Low
        $x_3_2 = {43 3a 5c 55 73 65 72 73 5c [0-32] 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c [0-80] 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c [0-80] 2e 70 64 62}  //weight: 3, accuracy: Low
        $x_1_3 = "ettings\\Shell\\Open\\command" ascii //weight: 1
        $x_1_4 = "ateExecute" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\System32\\fod" ascii //weight: 1
        $x_1_6 = "cmd.exe /c start C:\\Windows\\System32\\cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BypassUAC_SX_2147956728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.SX!MTB"
        threat_id = "2147956728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "botkiller" ascii //weight: 1
        $x_1_2 = "del /f /s /q" ascii //weight: 1
        $x_1_3 = "shutdown /r /f" ascii //weight: 1
        $x_1_4 = "vssadmin delete shadows" ascii //weight: 1
        $x_1_5 = "schtasks /create /tn \"Microsoft\\Windows\\UpdateOrchestrator\\SecurityUpdate\" /tr \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

