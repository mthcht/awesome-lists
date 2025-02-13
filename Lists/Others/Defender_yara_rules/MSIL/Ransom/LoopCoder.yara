rule Ransom_MSIL_LoopCoder_YAA_2147897653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LoopCoder.YAA!MTB"
        threat_id = "2147897653"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LoopCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 72 15 00 00 70 1b 6f 13 00 00 0a 2d 1e 07 72 1d 00 00 70 1b 6f 13 00 00 0a 2d 10}  //weight: 1, accuracy: High
        $x_1_2 = {12 09 28 21 00 00 0a 13 0a 72 ff 00 00 70}  //weight: 1, accuracy: High
        $x_1_3 = "ChangeExtension" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

