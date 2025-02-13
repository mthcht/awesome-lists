rule TrojanSpy_MSIL_Denmir_A_2147726061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Denmir.A!bit"
        threat_id = "2147726061"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Denmir"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StealHelper" ascii //weight: 1
        $x_1_2 = "Dendimirror Botnet" wide //weight: 1
        $x_1_3 = "schtasks /create /tn AzureSDKService" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

