rule Ransom_MSIL_McBurglar_GWT_2147832290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/McBurglar.GWT!MTB"
        threat_id = "2147832290"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "McBurglar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 1a 6f ?? ?? ?? 0a 00 07 06 16 06 8e 69 6f ?? ?? ?? 0a 00 07 11 04 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 06 02 19 73 ?? ?? ?? 0a 13 07 20 00 00 10 00 8d 23 00 00 01 13 08}  //weight: 10, accuracy: Low
        $x_1_2 = "README-MCBURGLAR.txt" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "MCB.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

