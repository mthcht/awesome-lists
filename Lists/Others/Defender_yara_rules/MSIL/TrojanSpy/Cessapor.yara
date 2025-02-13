rule TrojanSpy_MSIL_Cessapor_A_2147741663_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Cessapor.A!MTB"
        threat_id = "2147741663"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cessapor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BeHack\\BeHack\\obj\\x86\\Debug" ascii //weight: 1
        $x_1_2 = "BeHack: Chegada de Testes" wide //weight: 1
        $x_1_3 = "VerificarPasta" ascii //weight: 1
        $x_1_4 = "MoverMais4" ascii //weight: 1
        $x_1_5 = "EnviarAviso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

