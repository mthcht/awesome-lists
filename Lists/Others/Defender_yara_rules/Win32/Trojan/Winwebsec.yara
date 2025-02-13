rule Trojan_Win32_Winwebsec_RPC_2147835365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winwebsec.RPC!MTB"
        threat_id = "2147835365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 50 0c 73 3e 8b 58 04 8b ca 8b 50 18 8a 14 0a 32 54 18 60 8b 40 28 88 14 01 8b 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Winwebsec_RJ_2147848929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winwebsec.RJ!MTB"
        threat_id = "2147848929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d f8 81 e1 ff ff 00 00 ba 01 00 00 00 d3 e2 8b 45 fc 89 50 20 8b 4d f8 81 e1 ff ff 00 00 83 f9 18 74 25}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

