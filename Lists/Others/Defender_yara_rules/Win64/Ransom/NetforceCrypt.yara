rule Ransom_Win64_NetforceCrypt_PA_2147916802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/NetforceCrypt.PA!MTB"
        threat_id = "2147916802"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "NetforceCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".NetForceZ" ascii //weight: 1
        $x_1_2 = "ReadMe.txt" ascii //weight: 1
        $x_5_3 = "Your files have been encrypted by the NetForceZ's Ransomware." ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

