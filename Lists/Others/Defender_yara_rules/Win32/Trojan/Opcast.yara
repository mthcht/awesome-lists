rule Trojan_Win32_Opcast_SK_2147847483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Opcast.SK!MTB"
        threat_id = "2147847483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Opcast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uzxhnucssbdz" ascii //weight: 1
        $x_1_2 = "Y0U2U8A4" ascii //weight: 1
        $x_1_3 = "aNZ0g2B5P2e5h2H3V7o" ascii //weight: 1
        $x_1_4 = "pWh6G0U6o1N7q0g1D1QHd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

