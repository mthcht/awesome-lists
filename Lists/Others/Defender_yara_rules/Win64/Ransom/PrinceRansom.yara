rule Ransom_Win64_PrinceRansom_YAA_2147918525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PrinceRansom.YAA!MTB"
        threat_id = "2147918525"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PrinceRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Prince-Ransomware" ascii //weight: 1
        $x_1_2 = "Go buildinf:" ascii //weight: 1
        $x_1_3 = "files have been encrypted" ascii //weight: 1
        $x_1_4 = "paying us a ransom" ascii //weight: 1
        $x_1_5 = "not modify or rename encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_PrinceRansom_MX_2147935759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PrinceRansom.MX!MTB"
        threat_id = "2147935759"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PrinceRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Prince-Ransomware" ascii //weight: 1
        $x_1_2 = "Go build" ascii //weight: 1
        $x_1_3 = "EncryptDirectory" ascii //weight: 1
        $x_1_4 = "setWallpaper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_PrinceRansom_PA_2147947093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PrinceRansom.PA!MTB"
        threat_id = "2147947093"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PrinceRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Go build ID: \"" ascii //weight: 1
        $x_1_2 = "-Ransomware/encryption.EncryptFile" ascii //weight: 1
        $x_3_3 = {2d 6c 64 66 6c 61 67 73 3d 22 2d 48 3d 77 69 6e 64 6f 77 73 67 75 69 20 2d 73 20 2d 77 20 2d 58 20 27 [0-21] 2d 52 61 6e 73 6f 6d 77 61 72 65 2f 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 2e 50 75 62 6c 69 63 4b 65 79 3d}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

