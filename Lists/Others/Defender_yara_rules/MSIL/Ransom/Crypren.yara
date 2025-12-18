rule Ransom_MSIL_Crypren_A_2147745841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypren.A!MTB"
        threat_id = "2147745841"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypren"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\windows.dll" wide //weight: 1
        $x_1_2 = ".ciphered" wide //weight: 1
        $x_1_3 = "\\README_DONT_DELETE.txt" wide //weight: 1
        $x_5_4 = "n5Kq91XTymWeFvGN6DgZu5J2r4O8L9Bl" wide //weight: 5
        $x_5_5 = "nRzY7VKoOyfauQEqEWC2Dx9vlILp0AGB" wide //weight: 5
        $x_5_6 = "8b%CA2o{a}4KGg&75Sz!L$3jcX/96iH*" wide //weight: 5
        $x_5_7 = "0badc0debadc0de10badc0debadc0de1" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Crypren_NC_2147959750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypren.NC!MTB"
        threat_id = "2147959750"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypren"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ransomware.exe" ascii //weight: 2
        $x_1_2 = "EncryptFiles" ascii //weight: 1
        $x_2_3 = "RansomForm" ascii //weight: 2
        $x_1_4 = "deadline" ascii //weight: 1
        $x_1_5 = "TIME EXPIRED - FILES PERMANENTLY LOCKED" wide //weight: 1
        $x_1_6 = "DECRYPT_KEY.txt" wide //weight: 1
        $x_1_7 = ".encrypted" wide //weight: 1
        $x_1_8 = "CRITICAL SYSTEM ALERT" wide //weight: 1
        $x_1_9 = "Payment verification system offline" wide //weight: 1
        $x_1_10 = "Send Bitcoin to the provided address" wide //weight: 1
        $x_1_11 = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

