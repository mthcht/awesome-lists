rule VirTool_Win32_Ntpacker_2147606362_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ntpacker"
        threat_id = "2147606362"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ntpacker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1800"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 95 98 fe ff ff 33 c0 e8 ?? ?? ?? ?? 8b 85 ?? ?? ff ff e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b f0 6a 00 6a 00 6a 00 56}  //weight: 1000, accuracy: Low
        $x_100_2 = "ZwUnmapViewOfSection" ascii //weight: 100
        $x_100_3 = "WriteProcessMemory" ascii //weight: 100
        $x_100_4 = "CreateRemoteThread" ascii //weight: 100
        $x_100_5 = "CreateToolhelp32Snapshot" ascii //weight: 100
        $x_100_6 = "HTTP\\shell\\open\\command\\" ascii //weight: 100
        $x_100_7 = "shell_traywnd" ascii //weight: 100
        $x_100_8 = "svchost.exe" ascii //weight: 100
        $x_100_9 = "OpenThread" ascii //weight: 100
        $x_100_10 = "windir" ascii //weight: 100
        $x_100_11 = "GetWindowThreadProcessId" ascii //weight: 100
        $x_100_12 = "ReadProcessMemory" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 8 of ($x_100_*))) or
            (all of ($x*))
        )
}

