rule Trojan_Win32_VertexRat_AVR_2147963139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VertexRat.AVR!MTB"
        threat_id = "2147963139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VertexRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 b8 80 e5 41 00 8d b4 24 20 01 00 00 c6 84 24 b4 03 00 00 0a e8 ?? ?? ?? ?? 83 c4 04 8b c8 8d 84 24 e4 00 00 00 50 8b 44 24 1c c6 84 24 b4 03 00 00 0b e8 ?? ?? ?? ?? 83 c4 04 50 b8 6c e5 41 00}  //weight: 2, accuracy: Low
        $x_1_2 = {52 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff d6 8d 45 f0 50 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VertexRat_AV_2147982080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VertexRat.AV!MTB"
        threat_id = "2147982080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VertexRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vertexnet" ascii //weight: 1
        $x_1_2 = "vnmutex" ascii //weight: 1
        $x_1_3 = "vnlogs.log" ascii //weight: 1
        $x_1_4 = "HPORT" ascii //weight: 1
        $x_1_5 = "HKNAME" ascii //weight: 1
        $x_1_6 = "KAINT" ascii //weight: 1
        $x_1_7 = "120PVN_MUTEX16PA/login" ascii //weight: 1
        $x_1_8 = "PA30PAvnet80PA1PAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

