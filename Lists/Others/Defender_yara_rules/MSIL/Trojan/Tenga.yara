rule Trojan_MSIL_Tenga_AA_2147783096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tenga.AA!MTB"
        threat_id = "2147783096"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tenga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HttpWebResponse" ascii //weight: 1
        $x_1_2 = "WebHeaderCollection" ascii //weight: 1
        $x_1_3 = "<meta name=\"keywords\" content=\"([\\w\\d ]*)\">" ascii //weight: 1
        $x_1_4 = "apdocroto.gq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

