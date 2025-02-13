rule Trojan_Win32_Masscan_STE_2147773357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Masscan.STE"
        threat_id = "2147773357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Masscan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "match %s m" ascii //weight: 1
        $x_1_2 = "issuer[Kaspersky" ascii //weight: 1
        $x_1_3 = "MAN: \"ssdp:discover\"" ascii //weight: 1
        $x_1_4 = "-- blackrock" ascii //weight: 1
        $x_1_5 = "masscan -p80,8000-8100 10.0.0.0/8" ascii //weight: 1
        $x_1_6 = "subject[SomeOrganizationalUnit]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

