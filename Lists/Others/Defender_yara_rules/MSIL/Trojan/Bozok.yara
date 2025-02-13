rule Trojan_MSIL_Bozok_ARA_2147891512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bozok.ARA!MTB"
        threat_id = "2147891512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bozok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FVTVlcx/4tcJBSLTCQYCcl1C" wide //weight: 2
        $x_2_2 = "nSdFwJ23RYCdJ5Cvfa99iD2gCDzwEJyXkK99n324PZ" wide //weight: 2
        $x_2_3 = "WindowsApp58.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

