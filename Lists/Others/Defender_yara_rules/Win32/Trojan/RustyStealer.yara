rule Trojan_Win32_RustyStealer_ME_2147907648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RustyStealer.ME!MTB"
        threat_id = "2147907648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 fc 19 00 00 00 8b c3 0f b6 0e f7 75 fc 41 0f af cb 8a 44 15 d8 30 81 77 af 00 10 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RustyStealer_ADQ_2147923491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RustyStealer.ADQ!MTB"
        threat_id = "2147923491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 9c 24 8c 00 00 00 c1 84 24 8c 00 00 00 0c 8b 5c 24 3c 33 84 24 e8 00 00 00 c1 c5 10 01 ac 24}  //weight: 2, accuracy: High
        $x_2_2 = {c1 44 24 24 07 33 84 24 e0 00 00 00 89 c2 89 d8 c1 c2 07 c1 c0 07 89 54 24 48 8b 54 24 68 89 44 24 58 c1 c2 07 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

