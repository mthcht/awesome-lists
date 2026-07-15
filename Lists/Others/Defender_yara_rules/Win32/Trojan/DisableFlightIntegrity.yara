rule Trojan_Win32_DisableFlightIntegrity_A_2147973686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DisableFlightIntegrity.A"
        threat_id = "2147973686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DisableFlightIntegrity"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdedit" wide //weight: 1
        $x_1_2 = "set" wide //weight: 1
        $x_1_3 = "flightsigning off" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

