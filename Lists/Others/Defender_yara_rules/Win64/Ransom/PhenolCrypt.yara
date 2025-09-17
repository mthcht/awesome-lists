rule Ransom_Win64_PhenolCrypt_PA_2147952410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PhenolCrypt.PA!MTB"
        threat_id = "2147952410"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PhenolCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "You are encrypted!!!" ascii //weight: 3
        $x_1_2 = "Dear Sir/Madam,We are the PHENOL TeAm" ascii //weight: 1
        $x_1_3 = "2025 Ransomware Co." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

