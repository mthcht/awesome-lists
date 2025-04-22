rule Trojan_Win32_ProcessHijack_PA_2147743874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessHijack.PA!MTB"
        threat_id = "2147743874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 be f9 ff ff f7 d1 e8 00 00 00 00 5b 83 c3 11 93 ba 8f 3f 5d 1a 31 10 83 c0 04 e2 f9}  //weight: 1, accuracy: High
        $x_1_2 = {b9 41 06 00 00 e8 00 00 00 00 5b 83 c3 10 93 81 30 6b af 89 1d 83 c0 04 e2 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ProcessHijack_GTM_2147939658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessHijack.GTM!MTB"
        threat_id = "2147939658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 c1 8b 45 8c c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 89 54 24 08 89 4c 24 04 89 04 24}  //weight: 5, accuracy: High
        $x_5_2 = {8b 45 e4 8b 48 54 8b 45 08 8b 10 8b 45 e4 8b 40 34 89 c3 8b 45 8c c7 44 24 10 00 00 00 00 89 4c 24 0c 89 54 24 08 89 5c 24 04 89 04 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

