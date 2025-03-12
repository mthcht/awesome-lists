rule Ransom_Win64_WiperCrypt_PA_2147935810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/WiperCrypt.PA!MTB"
        threat_id = "2147935810"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "WiperCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".vico" ascii //weight: 1
        $x_1_2 = "Telegram Bot Client" wide //weight: 1
        $x_1_3 = "\\case_id.txt" ascii //weight: 1
        $x_1_4 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

