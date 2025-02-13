rule Trojan_Win32_Fodeweso_2147912293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fodeweso"
        threat_id = "2147912293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fodeweso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wsc_proxy" ascii //weight: 10
        $x_1_2 = "/runassvc" ascii //weight: 1
        $x_1_3 = "/rpcserver" ascii //weight: 1
        $x_1_4 = "/wsc_name" ascii //weight: 1
        $x_1_5 = "--disable" ascii //weight: 1
        $x_1_6 = "--firewall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

