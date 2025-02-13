rule Trojan_Win64_NoopDoor_GA_2147927355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NoopDoor.GA!MTB"
        threat_id = "2147927355"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NoopDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "14:19:55" ascii //weight: 1
        $x_1_2 = "gEztIattzpmPqRYIgcEn" ascii //weight: 1
        $x_1_3 = "GaFtoytVsKeSW" ascii //weight: 1
        $x_1_4 = "CryptGenRandom" ascii //weight: 1
        $x_1_5 = "CryptEncrypt" ascii //weight: 1
        $x_1_6 = "CryptDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

