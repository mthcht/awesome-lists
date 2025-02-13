rule Trojan_Win32_Synrat_A_2147628262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Synrat.A"
        threat_id = "2147628262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Synrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SynRat 2.1" ascii //weight: 1
        $x_1_2 = "DarkCoderSc" ascii //weight: 1
        $x_1_3 = "Wayting for server" ascii //weight: 1
        $x_1_4 = "Server Connected to Sin Client" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

