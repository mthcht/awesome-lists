rule Trojan_Win64_BarysStealer_RPX_2147849413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BarysStealer.RPX!MTB"
        threat_id = "2147849413"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BarysStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c7 83 ff 03 72 9b 45 85 ff 0f 85 85 fe ff ff 48 8b 55 f8 48 83 fa 10 0f 82 b2 fe ff ff 48 ff c2 48 8b 4d e0 48 8b c1 48 81 fa 00 10 00 00 0f 82 96 fe ff ff 48 83 c2 27 48 8b 49 f8 48 2b c1 48 83 c0 f8 48 83 f8 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BarysStealer_EM_2147851654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BarysStealer.EM!MTB"
        threat_id = "2147851654"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BarysStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {69 0e 00 c0 69 0e 00 c7 69 0e 00 ce 69 0e 00 d4 69 0e 00 da 69 0e 00 e0 69 0e 00 e6 69 0e 00 ec 69 0e 00 fa 69 0e 00 00 6a 0e 00 0b 6a 0e 00 11 6a 0e 00 17 6a 0e}  //weight: 7, accuracy: High
        $x_7_2 = {69 0e 00 c4 69 0e 00 ca 69 0e 00 d0 69 0e 00 d6 69 0e 00 dc 69 0e 00 ea 69 0e 00 f0 69 0e 00 fb 69 0e 00 01 6a 0e 00 07 6a 0e}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

