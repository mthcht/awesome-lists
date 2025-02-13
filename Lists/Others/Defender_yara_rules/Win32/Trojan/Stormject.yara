rule Trojan_Win32_Stormject_A_2147659327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stormject.A"
        threat_id = "2147659327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stormject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Storm ddos Server" ascii //weight: 1
        $x_1_2 = "Welcome to use storm ddos" ascii //weight: 1
        $x_1_3 = "StormServer.dll" ascii //weight: 1
        $x_10_4 = {50 ff d3 ff d0 80 65 ?? 00 8b c8 c6 45 ?? 55 c6 45 ?? 70 c6 45 ?? 64 c6 45 ?? 61 c6 45 ?? 74 c6 45 ?? 65}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

