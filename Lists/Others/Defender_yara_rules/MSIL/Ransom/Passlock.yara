rule Ransom_MSIL_Passlock_A_2147749901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Passlock.A!MTB"
        threat_id = "2147749901"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Passlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\PassLock\\PassLock\\obj\\Release\\PassLock.pdb" ascii //weight: 1
        $x_1_2 = "Stop, your files have been encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

