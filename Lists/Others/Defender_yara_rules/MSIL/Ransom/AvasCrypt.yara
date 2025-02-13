rule Ransom_MSIL_AvasCrypt_PA_2147815042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/AvasCrypt.PA!MTB"
        threat_id = "2147815042"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AvasCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WebRequest" ascii //weight: 1
        $x_1_2 = "Nmxaoyis" wide //weight: 1
        $x_1_3 = "91.243.44.142/arx-Xlopf_Xbkqkzns.png" wide //weight: 1
        $x_1_4 = "Waiting... {0}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

