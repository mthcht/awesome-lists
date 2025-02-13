rule VirTool_MSIL_MaliciousMSILLoaderLDR_A_2147695058_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/MaliciousMSILLoaderLDR.A"
        threat_id = "2147695058"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MaliciousMSILLoaderLDR"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "45|153|145|159|91|121|113|127" wide //weight: 1
        $x_1_2 = "14|90|125|111|114|84|119|122|115" wide //weight: 1
        $x_1_3 = "77|181|193|193|189|192|185|188|180|182|187" wide //weight: 1
        $x_1_4 = "88|188|199|192|204|189|165|204|189|159" wide //weight: 1
        $x_1_5 = "93|209|203|198|204|173|214|207|209|203|162" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

