rule Ransom_MSIL_Keygroup777_PA_2147916845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Keygroup777.PA!MTB"
        threat_id = "2147916845"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keygroup777"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Readm.txt" wide //weight: 1
        $x_1_2 = ".Keygroup777" wide //weight: 1
        $x_5_3 = "You became victim of the keygroup777 RANSOMWARE!" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

