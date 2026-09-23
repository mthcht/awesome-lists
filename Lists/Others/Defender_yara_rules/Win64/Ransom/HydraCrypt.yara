rule Ransom_Win64_HydraCrypt_KK_2147978333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HydraCrypt.KK!MTB"
        threat_id = "2147978333"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8d 0c 00 89 da 48 ff c0 d3 ea 83 e2 0f 83 c2 61 88 54 28 ff 48 83 f8 0c}  //weight: 20, accuracy: High
        $x_10_2 = "Global\\RANSOM_LOCK_A9F3E1" ascii //weight: 10
        $x_5_3 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 5
        $x_2_4 = "slammed.st" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_HydraCrypt_AMTB_2147978705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HydraCrypt!AMTB"
        threat_id = "2147978705"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Global\\RANSOM_LOCK_A9F3E1" ascii //weight: 2
        $x_1_2 = "ransomware.murphy" ascii //weight: 1
        $x_1_3 = " YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_4 = "You have 72 hours before the price doubles." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

