rule Trojan_Win32_Darkcomet_RPZ_2147889009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkcomet.RPZ!MTB"
        threat_id = "2147889009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b2 73 88 54 24 1e 88 54 24 1f b1 65 8d 54 24 18 52 8b f0 c6 44 24 1c 53 c6 44 24 1d 68 c6 44 24 1e 6f c6 44 24 1f 77 c6 44 24 20 4d 88 4c 24 21 c6 44 24 24 61 c6 44 24 25 67 88 4c 24 26 c6 44 24 27 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Darkcomet_MBYE_2147908353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkcomet.MBYE!MTB"
        threat_id = "2147908353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 36 40 00 9e f9 b0 01 00 ff ff ff 08 00 00 00 01 00 00 00 0a 00 06 00 e9 00 00 00 60 3b 40 00 e8 52 40 00 78 2c 40 00 78 00 00 00 7a 00 00 00 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Darkcomet_MBZ_2147941592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkcomet.MBZ!MTB"
        threat_id = "2147941592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 2f 40 00 b8 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 28 11 40 00 28 11 40 00 e4 10 40 00 78 00 00 00 80 00 00 00 8b 00 00 00 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

