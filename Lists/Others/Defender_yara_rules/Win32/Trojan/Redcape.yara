rule Trojan_Win32_Redcape_RPL_2147833877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcape.RPL!MTB"
        threat_id = "2147833877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcape"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 e8 8b 5d d4 8a 1c 1e 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d4 88 1c 31 8b 4d f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redcape_RPR_2147834935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcape.RPR!MTB"
        threat_id = "2147834935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcape"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d ec 8b 75 cc 8a 1c 37 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 cc 88 1c 31 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d c8 89 75 dc 89 4d d8 89 55 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

