rule Ransom_Win64_AnonCrypt_PA_2147943877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/AnonCrypt.PA!MTB"
        threat_id = "2147943877"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "AnonCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Anon-g Fox" ascii //weight: 3
        $x_1_2 = "Go build ID" ascii //weight: 1
        $x_1_3 = "Your files have been encrypted successfully!" ascii //weight: 1
        $x_1_4 = "This program can only run in Israel.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

