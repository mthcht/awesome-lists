rule Ransom_Win64_Cross_PA_2147845433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cross.PA!MTB"
        threat_id = "2147845433"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cross"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "current machine will be the target" ascii //weight: 1
        $x_1_2 = "Encrypt the specified path" ascii //weight: 1
        $x_1_3 = "DON'T RENAME, OR TRY TO DECRYPT " ascii //weight: 1
        $x_1_4 = "YOU WILL LOSE ALL YOU FILES AND DATA" ascii //weight: 1
        $x_10_5 = "You entire network has been compromised" ascii //weight: 10
        $x_10_6 = "encrypted and your sensitive data " ascii //weight: 10
        $x_10_7 = "buy the decryption app" ascii //weight: 10
        $x_10_8 = "data will be leaked" ascii //weight: 10
        $x_10_9 = "Go build ID:" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

