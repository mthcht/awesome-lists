rule Ransom_Win64_LockDownCrypt_PA_2147962091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockDownCrypt.PA!MTB"
        threat_id = "2147962091"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockDownCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LOCKDOWN RANSOMWARE" ascii //weight: 3
        $x_1_2 = ".crypt_lock" ascii //weight: 1
        $x_1_3 = "All your files are encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

