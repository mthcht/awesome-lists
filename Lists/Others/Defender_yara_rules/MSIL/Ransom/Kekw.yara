rule Ransom_MSIL_Kekw_AA_2147752400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Kekw.AA!MTB"
        threat_id = "2147752400"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kekw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KEKW.exe" ascii //weight: 2
        $x_1_2 = "repos\\KEKW\\obj\\Debug\\KEKW.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

