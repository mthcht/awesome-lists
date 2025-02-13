rule Adware_AndroidOS_Flurry99_A_329014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Flurry99.A"
        threat_id = "329014"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Flurry99"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_16_1 = "Java_com_flurry_sdk_na_Sogt" ascii //weight: 16
        $x_3_2 = "wdmngpr" ascii //weight: 3
        $x_3_3 = "vgrlaypr" ascii //weight: 3
        $x_3_4 = "avmtev" ascii //weight: 3
        $x_3_5 = "alrmpath" ascii //weight: 3
        $x_1_6 = "AES_CBC_decrypt" ascii //weight: 1
        $x_1_7 = "AES_CBC_encrypt" ascii //weight: 1
        $x_1_8 = "b64_decode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

