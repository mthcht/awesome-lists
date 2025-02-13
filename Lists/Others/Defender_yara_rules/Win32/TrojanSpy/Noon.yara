rule TrojanSpy_Win32_Noon_G_2147747813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Noon.G!MTB"
        threat_id = "2147747813"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 f3 8b 45 ?? 41 8a 54 15 ?? 30 54 01 ff 3b 4c 37 fc 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b c1 f7 f6 8b 45 ?? 41 8a 54 15 ?? 30 54 01 ff 3b 4c 3b ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {83 e1 03 74 ?? 8a 16 88 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Noon_CX_2147749168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Noon.CX!MTB"
        threat_id = "2147749168"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 f3 41 8a 44 15 f4 8b ?? ?? ?? ?? ?? 30 44 11 ff 3b 4c 37 fc 72 ?? 8b 4c 37 fc 68 ?? ?? ?? ?? 6a 40 51 52 ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? ff d0 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Noon_SJ_2147751816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Noon.SJ!MSR"
        threat_id = "2147751816"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MINATORYIMPERIUMCHRISTADELPHIANTWELVEMON" wide //weight: 1
        $x_1_2 = "Ambraernejuryprsi3" wide //weight: 1
        $x_1_3 = "UNAMENABLESTABEJSE" wide //weight: 1
        $x_1_4 = "Rkvrkscockie" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Noon_KH_2147755400_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Noon.KH!MTB"
        threat_id = "2147755400"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 33 c9 89 bd ?? ?? ?? ?? 85 db 74 1b 8d 49 ?? 8a 81 ?? ?? ?? ?? 30 04 3a 83 f9 ?? ?? ?? 33 c9 ?? ?? 41 42 3b d3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Noon_MD_2147755486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Noon.MD!MTB"
        threat_id = "2147755486"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 64 24 00 8a 91 ?? ?? ?? ?? 30 ?? ?? ?? ?? ?? 83 f9 ?? 75 ?? 33 c9 eb ?? 41 40 3b c6 72 ?? 8d ?? ?? 50 6a ?? 56 68 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

