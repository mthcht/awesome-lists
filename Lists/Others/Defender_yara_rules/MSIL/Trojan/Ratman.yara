rule Trojan_MSIL_Ratman_AMTB_2147978240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ratman!AMTB"
        threat_id = "2147978240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ratman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RatC2.Core" ascii //weight: 1
        $x_1_2 = "RATMAN_INFECT_ROOT" ascii //weight: 1
        $x_1_3 = "ratman:suo" ascii //weight: 1
        $x_1_4 = "ratman_infect.log" ascii //weight: 1
        $x_1_5 = "ratman:vcxproj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

