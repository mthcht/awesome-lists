rule Trojan_MSIL_DarkRat_AMTB_2147982534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkRat!AMTB"
        threat_id = "2147982534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DarkAgent RAT" ascii //weight: 2
        $x_1_2 = "rr88vipa.com" ascii //weight: 1
        $x_2_3 = "DarkAgent Client.pdb" ascii //weight: 2
        $x_2_4 = "RatVersion" ascii //weight: 2
        $x_1_5 = "DarkAgent_Client.src.Features.Stealers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

