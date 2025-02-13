rule Trojan_Win32_AutoitLeivion_RA_2147842269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitLeivion.RA!MTB"
        threat_id = "2147842269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitLeivion"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://157.245.157.93/oct" ascii //weight: 3
        $x_1_2 = "INETGET ( $SURL , $SDIRECTORY , 17 , 1 )" ascii //weight: 1
        $x_1_3 = "STRINGSPLIT ( $URLS , \",\" , 2 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

