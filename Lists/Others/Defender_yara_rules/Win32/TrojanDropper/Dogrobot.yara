rule TrojanDropper_Win32_Dogrobot_A_2147611579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dogrobot.A"
        threat_id = "2147611579"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c del " ascii //weight: 1
        $x_1_2 = "SYSTEM\\ControlSet003\\Services\\BITS\\Parameters" ascii //weight: 1
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Services\\BITS\\Parameters" ascii //weight: 1
        $x_1_4 = "ServiceDll" ascii //weight: 1
        $x_1_5 = "system32\\rundll32.exe" ascii //weight: 1
        $x_1_6 = " hello" ascii //weight: 1
        $x_1_7 = "%s%d_res.tmp" ascii //weight: 1
        $x_1_8 = "avp.exe" ascii //weight: 1
        $x_1_9 = "TEST_EVENT" ascii //weight: 1
        $x_1_10 = "\\BaseNamedObjects\\6953EA60-8D5F-4529-8710-42F8ED3E8CDA" wide //weight: 1
        $x_1_11 = "WinExec" ascii //weight: 1
        $x_1_12 = "CreateMutexA" ascii //weight: 1
        $x_1_13 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_14 = "ChangeServiceConfigA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Dogrobot_C_2147618533_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dogrobot.C"
        threat_id = "2147618533"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 83 c0 01 83 c0 01 83 c0 01 83 c0 01 61 60 b8 64 00 00 00 83 c0 01 83 c0 01 83 c0 01}  //weight: 1, accuracy: High
        $x_1_2 = {57 6a 03 6a 01 6a 10 56 56 53 ff 15 ?? ?? ?? ?? 8b ?? ff 15 ?? ?? ?? ?? 3d 31 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Dogrobot_E_2147626059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dogrobot.E"
        threat_id = "2147626059"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ext%s%dt.exe" ascii //weight: 1
        $x_1_2 = "te%s%dt.dll" ascii //weight: 1
        $x_1_3 = "@del 3596799a1543bc9f.aqq" ascii //weight: 1
        $x_1_4 = "afc9fe2f418b00a0.bat" ascii //weight: 1
        $x_1_5 = "\\\\.\\pcidump" ascii //weight: 1
        $x_1_6 = {0a c0 74 2e 8a 06 46 8a 27 47 38 c4 74 f2 2c 41 3c 1a}  //weight: 1, accuracy: High
        $x_1_7 = {ff ff 63 c6 85 ?? ?? ff ff 6d c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 20 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 20 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 20}  //weight: 1, accuracy: Low
        $x_2_8 = {ff ff 73 c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 76 c6 85 ?? ?? ff ff 68 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 74}  //weight: 2, accuracy: Low
        $x_2_9 = {8b 45 ec 03 45 d8 0f b6 00 83 c0 05 88 45 fc 6a 00 8d 45 e0 50 6a 01 8d 45 fc 50 ff 75 f4 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Dogrobot_F_2147627777_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dogrobot.F"
        threat_id = "2147627777"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 e4 6a 00 ff 15 ?? ?? 40 00 85 c0 74 ?? 90 8b 45 ec 03 45 d8 0f b6 00 83 c0 ?? 88 45 fc 68 c3 d1 3f 0f 6a 01 e8 ?? ?? ?? ?? 89 45 d0 6a 00 8d 45 e0 50 6a 01}  //weight: 1, accuracy: Low
        $x_1_2 = {72 65 63 79 63 6c 65 2e 7b ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7d 5c 6b 61 76 33 32 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Dogrobot_G_2147641424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dogrobot.G"
        threat_id = "2147641424"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 c0 0f 84 ?? ?? 00 00 81 7d ?? 02 76 19 89 0f 85 ?? ?? 00 00 8b 45 0c 39 45 ?? 74}  //weight: 2, accuracy: Low
        $x_2_2 = {c1 ee 0b 0f af f7 39 75 10 73 ?? 8b d6 be 00 08 00 00 2b f7 c1 fe 05 03 f0 d1 e3}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 5d 10 8b d3 83 c2 3c 8b ?? 03 ?? 83 c3 18 83 c3 10 8b 1b 8b 4d 0c 03 cb}  //weight: 1, accuracy: Low
        $x_1_4 = "\\\\.\\PciFtDisk" ascii //weight: 1
        $x_1_5 = "%c:\\Program files\\MSDN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

