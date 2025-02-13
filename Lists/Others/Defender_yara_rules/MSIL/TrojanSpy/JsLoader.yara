rule TrojanSpy_MSIL_JsLoader_SA_2147748615_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/JsLoader.SA!MSR"
        threat_id = "2147748615"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JsLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELE(" ascii //weight: 1
        $x_1_2 = "CT S(" ascii //weight: 1
        $x_1_3 = "FROM(" ascii //weight: 1
        $x_3_4 = "JssHttp" ascii //weight: 3
        $x_3_5 = "Host information report" wide //weight: 3
        $x_3_6 = "Here could be" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

