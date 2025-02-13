rule Trojan_Win32_Daws_PA_2147741261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daws.PA!MTB"
        threat_id = "2147741261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daws"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ineter Mc*1*|OFF|*appdata**trys.exe*" ascii //weight: 2
        $x_2_2 = "svhust*1*|OFF|*appdata*svhust\\*svhust.exe*" ascii //weight: 2
        $x_2_3 = "timer setting*1*|OFF|*appdata*Nboot\\*Nboot.exe*" ascii //weight: 2
        $x_2_4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Ineter Mc" wide //weight: 2
        $x_2_5 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svhust" wide //weight: 2
        $x_2_6 = {48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 00 00 57 00 72 00 69 00 74 00 65 00 4c 00 69 00 6e 00 65 00}  //weight: 2, accuracy: High
        $x_1_7 = "DetectWindows" ascii //weight: 1
        $x_1_8 = "WriteMe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Daws_MA_2147842169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daws.MA!MTB"
        threat_id = "2147842169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daws"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c8 89 cf f7 e6 c1 ea 03 8d 04 92 01 c0 29 c7 0f b6 87 ?? ?? ?? ?? 30 44 0d 00 83 c1 01 39 d9 75}  //weight: 5, accuracy: Low
        $x_2_2 = ":\\windows\\tasks\\windows.exe" ascii //weight: 2
        $x_2_3 = "skidhunter" ascii //weight: 2
        $x_2_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 2
        $x_2_5 = "schtasks /create /sc minute" ascii //weight: 2
        $x_2_6 = "/ru system" ascii //weight: 2
        $x_1_7 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_8 = "closesocket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Daws_EC_2147919724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daws.EC!MTB"
        threat_id = "2147919724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daws"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "copyfile" ascii //weight: 1
        $x_1_2 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "CurrentVersion\\Policies\\System\\EnableLUA" ascii //weight: 1
        $x_1_4 = "Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_5 = "SeRemoteShutdownPrivilege" ascii //weight: 1
        $x_1_6 = "WScript.Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

