rule Ransom_MSIL_Nano_A_2147942742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nano.A!MTB"
        threat_id = "2147942742"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nano"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dropRansomNote" ascii //weight: 1
        $x_1_2 = "Nano_Note.txt" ascii //weight: 1
        $x_1_3 = "Your files are encrypted by Nano Ransomware, meaning that your data is encrypted" ascii //weight: 1
        $x_1_4 = "you will need to pay for it" ascii //weight: 1
        $x_1_5 = "The payment is accepted only in Bitcoin" ascii //weight: 1
        $x_1_6 = "You should receive a reply from the same address, only this time with a decryption Key" ascii //weight: 1
        $x_1_7 = "decrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

