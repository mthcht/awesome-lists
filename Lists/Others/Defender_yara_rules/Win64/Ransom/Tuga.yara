rule Ransom_Win64_Tuga_YAQ_2147902635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Tuga.YAQ!MTB"
        threat_id = "2147902635"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Tuga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f 6e c2 66 0f fc d0 66 0f 6e 01 0f 57 d0 66 0f 7e 11 8d 47 04 66 0f 6e d8 66 0f 70 db 00 66 0f fe dd 66 0f 6f cb 66 0f 62 cb 66 0f 38 28 cc 66 0f 6f c3 66 0f 6a c3}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f 67 d2 66 0f 6e c2 66 0f fc d0 66 0f 6e 41 04 0f 57 d0 66 0f 7e 51 04 83 c7 08 48 8d 49 08}  //weight: 1, accuracy: High
        $x_10_3 = {7a 58 5b 58 56 67 18 16 6d 78 13 14 0f 21 6b 13}  //weight: 10, accuracy: High
        $x_10_4 = {79 59 54 59 55 66 1f 17 6e 79 6c 15 0c 20 6c 12}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_Tuga_DA_2147905279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Tuga.DA!MTB"
        threat_id = "2147905279"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Tuga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomTuga-master" ascii //weight: 1
        $x_1_2 = "You've been hacked" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Tuga_GDR_2147905388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Tuga.GDR!MTB"
        threat_id = "2147905388"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Tuga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/x64/Release/DataDecryptor.exe" ascii //weight: 1
        $x_1_2 = "x64/Release/debugFolder_backup/pdfsample.pdf" ascii //weight: 1
        $x_1_3 = "./emailSender.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Tuga_SKH_2147913915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Tuga.SKH!MTB"
        threat_id = "2147913915"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Tuga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomTuga.exe" ascii //weight: 1
        $x_1_2 = "state not recoverable" ascii //weight: 1
        $x_1_3 = "owner dead" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

