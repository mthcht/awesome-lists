rule Trojan_MSIL_RRat_PGRR_2147957696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RRat.PGRR!MTB"
        threat_id = "2147957696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "0104202319918KLDFIJDRFOGZKAFREXRXHDZGFXHAKHEAKXAGKGDAHKAYDLFGKDOHZFZATGZFDLFXHDEZJGZGHDPFQLAGXGFJDZFKAGZDXFPFGFHLZKGHZHFHLDJA" ascii //weight: 3
        $x_3_2 = "178973406770.My.Resources" ascii //weight: 3
        $x_3_3 = "o411366791f204c459ff919e0401e89e1" ascii //weight: 3
        $x_1_4 = "15686204.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

