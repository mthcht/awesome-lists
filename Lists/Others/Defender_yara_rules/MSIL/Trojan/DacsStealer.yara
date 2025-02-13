rule Trojan_MSIL_DacsStealer_A_2147893034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DacsStealer.A!MTB"
        threat_id = "2147893034"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DacsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hHZXQtV21pT2JqZWN0ICAiV2luMzJfVmlkZW9Db250cm9sbGVyIiB8IFNl" wide //weight: 2
        $x_2_2 = "bGVjdC1PYmplY3QgIkFkYXB0ZXJEQUNUeXBlIikgfCBPdXQtU3RyaW5n" wide //weight: 2
        $x_2_3 = "D0oR2V0LVdtaU9iamVjdCAgIldpbjMyX0Rpc2tEcml2ZSIgfCBTZWxlY3Qt" wide //weight: 2
        $x_2_4 = "T2JqZWN0ICAiU2VyaWFsTnVtYmVyInwgU2VsZWN0LU9iamVjdCAtRmlyc3Q" wide //weight: 2
        $x_2_5 = "U9KChHZXQtV21pT2JqZWN0ICJXaW4zMl9DYWNoZU1lbW9yeSIgfCBTZWxlY3Qt" wide //weight: 2
        $x_2_6 = "T2JqZWN0ICJwdXJwb3NlIiB8IFNlbGVjdC1PYmplY3QgLUZpcnN" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

