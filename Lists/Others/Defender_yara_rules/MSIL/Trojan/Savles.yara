rule Trojan_MSIL_Savles_A_2147681967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Savles.A"
        threat_id = "2147681967"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Savles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "save&t=process&ed=1&d=" wide //weight: 1
        $x_1_2 = "save&t=files&d=[ndc]" wide //weight: 1
        $x_1_3 = "iupload&t=1" wide //weight: 1
        $x_1_4 = "txt.xCdNx" wide //weight: 1
        $x_1_5 = "t- f- l- nwodtuhS" wide //weight: 1
        $x_1_6 = "=dmc&noitcnuf" wide //weight: 1
        $x_1_7 = "daolpu" wide //weight: 1
        $x_1_8 = "=resu&" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Savles_B_2147685537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Savles.B"
        threat_id = "2147685537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Savles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "save&t=process&ed=1&d=" wide //weight: 1
        $x_1_2 = "save&t=files&d=[ndc]" wide //weight: 1
        $x_1_3 = "iupload&t=1" wide //weight: 1
        $x_1_4 = "YUhSMGNEb3" wide //weight: 1
        $x_1_5 = "ZUU1a1EzZ3VkSGgw" wide //weight: 1
        $x_1_6 = "TG1WNFpRPT0=" wide //weight: 1
        $x_1_7 = "YVc1a1pYZ3VjR2h3UDNCamJtRnRaVDA9" wide //weight: 1
        $x_1_8 = "Wm5WdVkzUnBiMjRtWTIxa1BRPT0=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

