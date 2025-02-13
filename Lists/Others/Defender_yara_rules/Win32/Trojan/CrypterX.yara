rule Trojan_Win32_CrypterX_DSK_2147741062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrypterX.DSK!MTB"
        threat_id = "2147741062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrypterX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XTn*E1rJZcdCA{2cyrIQnsCs0" ascii //weight: 1
        $x_1_2 = "gyXDVp0vtS5Zujs" ascii //weight: 1
        $x_1_3 = {8b c1 33 d2 f7 f3 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CrypterX_RPL_2147818501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrypterX.RPL!MTB"
        threat_id = "2147818501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrypterX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 86 f2 a1 42 00 8b 45 fc 8d 88 f0 a1 42 00 b8 1f 85 eb 51 03 ce f7 e1 8b ce c1 ea 03 6b c2 19 2b c8 0f b6 81 03 68 42 00 30 86 f3 a1 42 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

