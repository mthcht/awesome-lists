rule TrojanSpy_Win32_Weecnaw_D_2147734557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Weecnaw.D!bit"
        threat_id = "2147734557"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Weecnaw"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powercat -l -p 4000 -r tcp" ascii //weight: 1
        $x_1_2 = "del \"%%~f0\"&exit /b" ascii //weight: 1
        $x_1_3 = "%TEMP%\\powercat.ps1" ascii //weight: 1
        $x_1_4 = "%TEMP%\\loopc.cmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Weecnaw_G_2147742534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Weecnaw.G!MTB"
        threat_id = "2147742534"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Weecnaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 eb 02 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 8d a0 e7 ff ff e8 4c f7 fa ff 6a 04}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 29 55 51 00 ae 11 1f 22 ad 78 0e 97 e3 f5 80 e0 58 88 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Weecnaw_GC_2147760763_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Weecnaw.GC!MTB"
        threat_id = "2147760763"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Weecnaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 8d 1c 01 30 13 41 81 f9}  //weight: 1, accuracy: High
        $x_1_2 = {80 34 01 70 [0-16] 41 89 d3 [0-32] 39 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Weecnaw_GN_2147760764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Weecnaw.GN!MTB"
        threat_id = "2147760764"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Weecnaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 13 0b 11 04 11 06 11 0a 58 11 09 11 0a 91 11 0b 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d8}  //weight: 1, accuracy: High
        $x_1_2 = {04 1f 1d 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 0a 02 4a 06 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

