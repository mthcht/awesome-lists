rule Ransom_MSIL_Vertex_AMTB_2147966341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Vertex!AMTB"
        threat_id = "2147966341"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vertex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VertexNet Ransomware Started" ascii //weight: 1
        $x_1_2 = "VertexNetStage2" ascii //weight: 1
        $x_1_3 = "vertexnet.log" ascii //weight: 1
        $x_1_4 = ".vertex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

