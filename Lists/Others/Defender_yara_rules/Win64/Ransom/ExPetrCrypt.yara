rule Ransom_Win64_ExPetrCrypt_PA_2147899987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ExPetrCrypt.PA!MTB"
        threat_id = "2147899987"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ExPetrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomAware" wide //weight: 1
        $x_1_2 = "worth of Bitcoin to this address:" wide //weight: 1
        $x_1_3 = "Ooops, your files have been encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

