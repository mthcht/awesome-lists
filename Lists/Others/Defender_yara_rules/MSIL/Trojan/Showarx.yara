rule Trojan_MSIL_Showarx_A_2147720136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Showarx.A"
        threat_id = "2147720136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Showarx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "://goodwebshow.com/redirect/57a764d042bf8" ascii //weight: 8
        $x_3_2 = "AdsShow.exe" ascii //weight: 3
        $x_2_3 = "\\Projects\\AdsShow\\" ascii //weight: 2
        $x_2_4 = "\\AdsShow\\obj\\" ascii //weight: 2
        $x_2_5 = "\\AdsShow.pdb" ascii //weight: 2
        $x_1_6 = {53 6c 65 65 70 00 41 64 64 54 6f 53 74 61 72 74 75 70 00 43 75 72 72 65 6e 74 55 73 65 72}  //weight: 1, accuracy: High
        $x_1_7 = "\\sami\\Documents\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

