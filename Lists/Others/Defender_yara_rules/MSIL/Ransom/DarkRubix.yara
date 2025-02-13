rule Ransom_MSIL_DarkRubix_S_2147752002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/DarkRubix.S!MTB"
        threat_id = "2147752002"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkRubix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CryptoDarkRubix" wide //weight: 1
        $x_1_2 = "\\darkrubixhacking.jpg" wide //weight: 1
        $x_1_3 = "\\unlockFiles.txt" wide //weight: 1
        $x_1_4 = "Hi your current ID is \"" wide //weight: 1
        $x_1_5 = "If you had problem sent email to sudeio@geto.tk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

