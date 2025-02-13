rule Trojan_Win32_Adject_A_2147609338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adject.A"
        threat_id = "2147609338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?id=%s&app=REP\" border=0" ascii //weight: 1
        $x_1_2 = "<img src=\"http://www.%s" ascii //weight: 1
        $x_1_3 = "?u=%s&t=%s&w=%s&id=%s" ascii //weight: 1
        $x_1_4 = "PRESCRIPTION" ascii //weight: 1
        $x_1_5 = "VUITTON" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

