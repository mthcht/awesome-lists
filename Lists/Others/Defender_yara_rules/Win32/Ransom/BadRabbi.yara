rule Ransom_Win32_BadRabbi_SL_2147756908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BadRabbi.SL!MTB"
        threat_id = "2147756908"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BadRabbi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Bad Rabbit Ransonware" wide //weight: 5
        $x_2_2 = "The price you have to pay to decryption is:" wide //weight: 2
        $x_5_3 = "RansonMail" wide //weight: 5
        $x_2_4 = "This is your recovery key:" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

