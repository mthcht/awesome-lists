rule Ransom_MSIL_Troli_A_2147689176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Troli.A"
        threat_id = "2147689176"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Troli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iTorLock" ascii //weight: 1
        $x_1_2 = "*.cry" wide //weight: 1
        $x_1_3 = "PaymentCeck$" wide //weight: 1
        $x_1_4 = "SendMessage&User=true&Iron=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Troli_B_2147728569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Troli.B!bit"
        threat_id = "2147728569"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Troli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".cry" wide //weight: 1
        $x_1_2 = "RijndaelManaged" ascii //weight: 1
        $x_1_3 = "processkiller" ascii //weight: 1
        $x_1_4 = "startdesktop" ascii //weight: 1
        $x_1_5 = "autorun.inf" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

