rule Ransom_Win64_MajinCrypt_PA_2147976334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MajinCrypt.PA!MTB"
        threat_id = "2147976334"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MajinCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "majin.bmp" ascii //weight: 3
        $x_1_2 = "M A J I N A H A N A S H I" ascii //weight: 1
        $x_1_3 = "delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

