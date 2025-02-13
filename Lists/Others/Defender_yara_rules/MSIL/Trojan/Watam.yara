rule Trojan_MSIL_Watam_A_2147695750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Watam.A"
        threat_id = "2147695750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Watam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "twitter.com/xbillybobx" wide //weight: 10
        $x_1_2 = "WTF IS THIS?" wide //weight: 1
        $x_1_3 = "\\svchost\\sl.mpg" wide //weight: 1
        $x_1_4 = "ConnectToServer" ascii //weight: 1
        $x_1_5 = "\\sims\\UserData" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

