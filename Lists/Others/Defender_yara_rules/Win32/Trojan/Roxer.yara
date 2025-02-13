rule Trojan_Win32_Roxer_EC_2147838539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Roxer.EC!MTB"
        threat_id = "2147838539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Roxer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {88 8d f8 fe ff ff 8a cb c1 ea 03 0f be c2 6b c0 19 69 db 0d 66 19 00 2a c8 b8 1f 85 eb 51 81 c3 5c f3 6e 3c 80 c1 61 f7 e3 88 8d f9 fe ff ff}  //weight: 7, accuracy: High
        $x_7_2 = {69 c9 0d 66 19 00 33 d2 6a 19 5f 81 c1 5c f3 6e 3c 8b c1 f7 f7 80 c2 61 88 94 35 f4 fd ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Roxer_CCAJ_2147889448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Roxer.CCAJ!MTB"
        threat_id = "2147889448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Roxer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e6 c1 ea ?? 8d 04 92 8b d6 2b d0 8a 04 95 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 3b f1 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

