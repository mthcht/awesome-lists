rule Ransom_Win64_Pe32Skip_YAC_2147933901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Pe32Skip.YAC!MTB"
        threat_id = "2147933901"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Pe32Skip"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "payment is required." ascii //weight: 1
        $x_1_2 = "What drive do you want to encrypt" ascii //weight: 1
        $x_1_3 = "files have been encrypted" ascii //weight: 1
        $x_1_4 = "payment is required" ascii //weight: 1
        $x_1_5 = "Please note that cost for file decryption and avoiding data publification is separate." ascii //weight: 1
        $x_1_6 = "decryption test" ascii //weight: 1
        $x_10_7 = "lock.pe32Skip" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

