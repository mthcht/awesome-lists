rule Ransom_MSIL_GandCrab_B_2147728527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/GandCrab.B!bit"
        threat_id = "2147728527"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptFile" ascii //weight: 1
        $x_1_2 = "EncryptFolder" ascii //weight: 1
        $x_1_3 = "CreatePass" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = ".CRAB" wide //weight: 1
        $x_1_6 = "Send $100 worth of bitcoin to this address" wide //weight: 1
        $x_1_7 = "all your personal files have been encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_GandCrab_A_2147728628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/GandCrab.A!bit"
        threat_id = "2147728628"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptFile" ascii //weight: 1
        $x_1_2 = "EncryptFolder" ascii //weight: 1
        $x_1_3 = "CreatePass" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
        $x_1_5 = "Screenshot_1" ascii //weight: 1
        $x_1_6 = "who_accepts_bitcoins_as_payment" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

