rule Trojan_AndroidOS_KimSuky_A_2147834507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/KimSuky.A"
        threat_id = "2147834507"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "KimSuky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/kisa/mobile_security" ascii //weight: 1
        $x_2_2 = "4d3537c428f49696b78b115a8c2877b8633264d4" ascii //weight: 2
        $x_2_3 = "Some permissions are denied. The app may not work correctly" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

