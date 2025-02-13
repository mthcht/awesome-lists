rule Ransom_MSIL_Spectre_RPZ_2147834439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Spectre.RPZ!MTB"
        threat_id = "2147834439"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spectre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locked" wide //weight: 1
        $x_1_2 = ".killswitch" wide //weight: 1
        $x_1_3 = "codingserver.000webhostapp.com" wide //weight: 1
        $x_1_4 = "Spectre Decryptor" wide //weight: 1
        $x_1_5 = "Decrypt Files" wide //weight: 1
        $x_1_6 = "Your Data will be decrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

