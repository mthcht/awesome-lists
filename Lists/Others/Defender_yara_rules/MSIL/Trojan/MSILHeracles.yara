rule Trojan_MSIL_MSILHeracles_SN_2147968908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MSILHeracles.SN!MTB"
        threat_id = "2147968908"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILHeracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$1F8B2271-7303-4F2F-8B4B-556A5FCB3C86" ascii //weight: 2
        $x_1_2 = "I am virus! " ascii //weight: 1
        $x_1_3 = "Fuck You :-)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

