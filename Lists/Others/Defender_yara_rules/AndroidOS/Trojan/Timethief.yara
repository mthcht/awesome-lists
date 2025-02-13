rule Trojan_AndroidOS_Timethief_A_2147845225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Timethief.A"
        threat_id = "2147845225"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Timethief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/example/funapp/MainActivity;" ascii //weight: 2
        $x_2_2 = "You have successfully registered use Prev and Next buttons. Enjoy with the fun Pictures..." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

