rule Trojan_Win32_Lmir_BMN_2147596915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lmir.BMN"
        threat_id = "2147596915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WinSysM" ascii //weight: 10
        $x_10_2 = "http://ekey.sdo.com" ascii //weight: 10
        $x_10_3 = "MM.DLL" ascii //weight: 10
        $x_10_4 = "Mir.exe" ascii //weight: 10
        $x_10_5 = "Woool" ascii //weight: 10
        $x_10_6 = "mir1.dat" ascii //weight: 10
        $x_10_7 = "IGM.exe" ascii //weight: 10
        $x_2_8 = "\\drivers\\etc\\hosts" ascii //weight: 2
        $x_2_9 = "\\HOSTS" ascii //weight: 2
        $x_2_10 = "CreateToolhelp32Snapshot" ascii //weight: 2
        $x_2_11 = "Toolhelp32ReadProcessMemory" ascii //weight: 2
        $x_2_12 = "OpenProcess" ascii //weight: 2
        $x_2_13 = "ShellExecute" ascii //weight: 2
        $x_2_14 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_15 = "avpcc." ascii //weight: 2
        $x_2_16 = "avpm." ascii //weight: 2
        $x_2_17 = "avp32." ascii //weight: 2
        $x_2_18 = "avp." ascii //weight: 2
        $x_2_19 = "antivirus.e" ascii //weight: 2
        $x_2_20 = "fsav.exe" ascii //weight: 2
        $x_2_21 = "norton.e" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 10 of ($x_2_*))) or
            ((7 of ($x_10_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lmir_D_2147607412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lmir.D"
        threat_id = "2147607412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 1b 56 8b fe bb ?? ?? ?? ?? 83 fb 00 74 08 ac c0 c8 ?? aa 4b eb f3 5e 66 c7 06 4d 5a}  //weight: 2, accuracy: Low
        $x_1_2 = {8b fe ac 0a c0 74 05 34 8b aa eb f6 47 ac 0a c0 75 f5 c3 08 00 2f 74 17 be}  //weight: 1, accuracy: Low
        $x_1_3 = {74 62 81 3e 47 49 44 3a 75 f2 83 c6 05 6a 0d 56 8d 85 ?? ?? ff ff 50 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {54 58 54 3d 49 44 3a 25 73 2c 50 61 73 73 3a 25 73 2c 4e 6f 3a 25 73 2c 53 4e 3a 25 73 2c 4d 42 3a 25 73 00}  //weight: 1, accuracy: High
        $x_2_5 = {80 38 e9 75 0f b9 2b e1 c1 e9 c7 00 2b e1 c1 e9 c6 40 04 02 0f 20 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 82 01 00 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

