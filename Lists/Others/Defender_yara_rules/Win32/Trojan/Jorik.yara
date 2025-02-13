rule Trojan_Win32_Jorik_B_2147681356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jorik.B"
        threat_id = "2147681356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jorik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 04 b6 33 c9 33 d2 89 4c 24 0c 8d 04 80 89 54 24 18 89 4c 24 10 89 4c 24 14 8d 04 80 52 8d 4c 24 28 89 54 24 20 c1 e0 03}  //weight: 1, accuracy: High
        $x_1_2 = "af!i&d9" ascii //weight: 1
        $x_1_3 = "Kill You" ascii //weight: 1
        $x_1_4 = "cmd.exe /c \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jorik_MA_2147819026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jorik.MA!MTB"
        threat_id = "2147819026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jorik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 32 34 30 32 33 2d 35 39 32 2d 31 32 33 3d 31 32 2d 33 34 2d 32 33 30 34 2d 3d 32 33 30 35 00 2e 00 00 00 00 01 00 12 00 9c e3 40}  //weight: 1, accuracy: High
        $x_1_2 = {f4 01 00 00 9c e3 40 00 00 00 00 00 80 19 42 00 e0 81 45 00 e8 74 00 00 08 90 45 00 f6 50 40 00 00 90 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jorik_MB_2147824225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jorik.MB!MTB"
        threat_id = "2147824225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jorik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 74 fd ff ff 03 05 ?? ?? ?? ?? 8b 08 03 0d ?? ?? ?? ?? 8b 95 74 fd ff ff 03 15 ?? ?? ?? ?? 89 0a a1 ?? ?? ?? ?? 83 c0 71 8b 8d 74 fd ff ff 03 0d ?? ?? ?? ?? 33 01 8b 95 74 fd ff ff 03 15 ?? ?? ?? ?? 89 02 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 03 55 f8 8a 45 f4 88 02 eb}  //weight: 1, accuracy: High
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = ".icm\\PersistentHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

