rule Trojan_Win32_Woool_GVA_2147955883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Woool.GVA!MTB"
        threat_id = "2147955883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Woool"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac 80 cb 61 0f a3 db 08 c3 f5 34 55 f6 d3 68 bd 65 cd a0 fe c8 18 e3 f6 d8 66 0f ba e1 05 fe cb f6 db 34 73 8a 5c 24 08 b3 da 50 fe c8 53 aa f6 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Woool_GVB_2147955884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Woool.GVB!MTB"
        threat_id = "2147955884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Woool"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe c0 49 66 ff c9 83 c6 01 f8 66 0f be c9 30 c3 80 d5 3e f5 d2 dd 0f b6 c0 66 0f be c8 8b 0c 85 ?? ?? ?? ?? f9 f7 d9 f6 c2 3c f5 88 14 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

