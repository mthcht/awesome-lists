rule Trojan_MSIL_TinyShadow_A_2147947060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TinyShadow.A!dha"
        threat_id = "2147947060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TinyShadow"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 77 00 69 00 74 00 63 00 68 00 20 00 74 00 6f 00 20 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "BQUFBQUFBQUFBQUFBQUFBQ==" wide //weight: 1
        $x_1_3 = "{0};0{1}: {2}" wide //weight: 1
        $x_1_4 = ":17896####################################################################################################" wide //weight: 1
        $x_1_5 = "14.0.0.0" wide //weight: 1
        $x_1_6 = "c_sharp.exe" ascii //weight: 1
        $x_1_7 = "31d5e991-8ede-469c-b960-a2dd32acb44e" ascii //weight: 1
        $x_1_8 = "o4rygCfC6YAhvlQosg" ascii //weight: 1
        $x_1_9 = "o1MMNCdJrGBKWR4dmfg" ascii //weight: 1
        $x_1_10 = "otOUGfM4CFFzNZbamew" ascii //weight: 1
        $x_1_11 = "ogYgfmEIJrtiDf3p0FA" ascii //weight: 1
        $x_1_12 = "TlNtJT2IeNPc" ascii //weight: 1
        $x_1_13 = "initial_url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

