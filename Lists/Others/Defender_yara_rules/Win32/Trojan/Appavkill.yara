rule Trojan_Win32_Appavkill_A_2147749946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Appavkill.A!MSR"
        threat_id = "2147749946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Appavkill"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vcmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & taskkill /f /im %s & Del /f /q \"%s\"" wide //weight: 1
        $x_1_2 = "cmd.exe /c reg delete HKLM\\System\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_1_3 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\" & sc delete WindowsDeviceACL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

