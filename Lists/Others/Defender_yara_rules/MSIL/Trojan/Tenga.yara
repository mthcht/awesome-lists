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

rule Trojan_MSIL_Tenga_PKZM_2147935010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tenga.PKZM!MTB"
        threat_id = "2147935010"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tenga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 0b 01 00 70 20 2e 04 00 00 73 1d 00 00 06 73 4a 00 00 0a 0a 25 06 6f ?? 00 00 0a 6f ?? 00 00 06 0b 06 6f ?? 00 00 0a 6f ?? 00 00 06 0c 18 8d 34 00 00 01 25 16 07 a2 25 17 08 a2 28 ?? 00 00 0a 6f ?? 00 00 0a de 03}  //weight: 3, accuracy: Low
        $x_1_2 = "SvchostController.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

