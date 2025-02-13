rule Ransom_Win64_SmertCrypt_PA_2147917422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SmertCrypt.PA!MTB"
        threat_id = "2147917422"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SmertCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tdsoperational.pythonanywhere.com" ascii //weight: 1
        $x_1_2 = "\\README.txt" ascii //weight: 1
        $x_4_3 = "Your files have been fucked" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

