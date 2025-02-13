rule Trojan_Win32_Nanobot_RPU_2147837482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanobot.RPU!MTB"
        threat_id = "2147837482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 53 83 c3 27 03 c3 33 c0 bb 26 00 00 00 2b d8 33 db 33 c3 2b d8 33 db 83 eb 1e 2b d8 33 c0 81 c3 97 00 00 00 58 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanobot_SPQ_2147840560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanobot.SPQ!MTB"
        threat_id = "2147840560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {bb 26 00 00 00 2b d8 33 db 33 c3 2b d8 33 db 83 eb 1e 2b d8 33 c0 81 c3 97 00 00 00 03 c3 2b c0 05 97 00 00 00 83 c3 68 8b c3 58 5b 8b 45 fc 99 b9 5f 00 00 00 f7 f9 8b 45 fc 8b 4d e4 8a 14 11 88 94 05 d8 fd ff ff}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

