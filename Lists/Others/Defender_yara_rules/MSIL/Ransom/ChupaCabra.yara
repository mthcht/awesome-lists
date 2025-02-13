rule Ransom_MSIL_ChupaCabra_MK_2147782544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ChupaCabra.MK!MTB"
        threat_id = "2147782544"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ChupaCabra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware" ascii //weight: 1
        $x_1_2 = "HowToDecrypt.txt" ascii //weight: 1
        $x_1_3 = "All your files are encrypted" ascii //weight: 1
        $x_1_4 = "http://anubiscloud.xyz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

