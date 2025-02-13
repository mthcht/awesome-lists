rule Trojan_Win32_Rungent_A_2147735435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rungent.A"
        threat_id = "2147735435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rungent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://160.202.162.147/1.tmp" ascii //weight: 1
        $x_1_2 = "http://5.149.254.25/1.tmp" ascii //weight: 1
        $x_1_3 = "%s\\Microsofts HeIp\\template_%x.DATAHASH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

