rule Trojan_Win32_Movivarch_A_2147680308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Movivarch.A"
        threat_id = "2147680308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Movivarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yapson" wide //weight: 1
        $x_1_2 = "panelsms" wide //weight: 1
        $x_1_3 = "1960&codigo" wide //weight: 1
        $x_1_4 = "caption:{0}" wide //weight: 1
        $x_1_5 = "otherCountriesLocationOtherCountries:{41}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

