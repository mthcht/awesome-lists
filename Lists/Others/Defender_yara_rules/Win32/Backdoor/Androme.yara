rule Backdoor_Win32_Androme_PA_2147741347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androme.PA!MTB"
        threat_id = "2147741347"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androme"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AppData@-@jrun32.exe@-@jrun32" ascii //weight: 2
        $x_2_2 = "AppData@-@explorrer32.exe@-@explorrer32" ascii //weight: 2
        $x_1_3 = "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v" wide //weight: 1
        $x_1_4 = "/t REG_SZ /d" wide //weight: 1
        $x_1_5 = "-notray" wide //weight: 1
        $x_1_6 = "RemoteHook" ascii //weight: 1
        $x_1_7 = "PE_INSTALL" ascii //weight: 1
        $x_1_8 = "\\system32\\ipconfig.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Androme_PB_2147744465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androme.PB!MTB"
        threat_id = "2147744465"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androme"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {46 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8b 84 b5 ?? ?? ?? ?? 03 45 ?? 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 89 45 f0 8a 84 b5 ?? ?? ?? ?? 8b 55 ?? 8b 94 95 ?? ?? ?? ?? 89 94 b5 ?? ?? ?? ?? 25 ff 00 00 00 8b 55 ?? 89 84 95 ?? ?? ?? ?? 8b 84 b5 ?? ?? ?? ?? 8b 55 ?? 03 84 95 ?? ?? ?? ?? 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 ?? ?? ?? ?? 8b 55 ?? 30 04 3a 47 4b 0f 85}  //weight: 10, accuracy: Low
        $x_1_2 = ":\\ Connected" ascii //weight: 1
        $x_1_3 = "Eject USB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Androme_MR_2147766851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androme.MR!MTB"
        threat_id = "2147766851"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androme"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 13 89 42 ?? 8b 03 8b 16 89 50 ?? 8b 03 89 06 83 03 ?? 8b 03 2b 45 ?? 3d 12 00 8b 03 c6 00 ?? 8b 45 ?? 8d 50 ?? 8b 03 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {2b d0 8b c2 c3 03 00 83 c0}  //weight: 10, accuracy: Low
        $x_1_3 = "vcltest3.dll" ascii //weight: 1
        $x_1_4 = "T__RUndo.pas" ascii //weight: 1
        $x_1_5 = "T__RGroup.pas" ascii //weight: 1
        $x_1_6 = "T___myBzr" ascii //weight: 1
        $x_10_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

