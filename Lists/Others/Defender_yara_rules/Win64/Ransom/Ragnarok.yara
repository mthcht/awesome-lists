rule Ransom_Win64_Ragnarok_BR_2147837819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Ragnarok.BR!MTB"
        threat_id = "2147837819"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Ragnarok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_2 = "ANY MODIFICATION/RESTORATION ATTEMPTS WILL BREAK YOUR FILES AND YOU WILL NOT BE ABLE TO RECOVER THEM EVER AGAIN" ascii //weight: 1
        $x_1_3 = "DO NOT TOUCH ANYTHING" ascii //weight: 1
        $x_1_4 = "TO DECRYPT/RESTORE YOUR FILES -> WRITE AN EMAIL TO THIS ADDRESS FOR FURTHER INSTRUCTIONS" ascii //weight: 1
        $x_1_5 = "crustom-support@proton.me" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

