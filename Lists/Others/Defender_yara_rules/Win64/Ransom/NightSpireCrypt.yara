rule Ransom_Win64_NightSpireCrypt_PA_2147945685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/NightSpireCrypt.PA!MTB"
        threat_id = "2147945685"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "NightSpireCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".onion" ascii //weight: 1
        $x_1_2 = "readme.txt" ascii //weight: 1
        $x_1_3 = "nightspireteam" ascii //weight: 1
        $x_2_4 = "Your servers and files are locked and copied." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

