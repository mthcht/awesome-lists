rule Ransom_Win64_MadiLockCrypt_PA_2147945552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MadiLockCrypt.PA!MTB"
        threat_id = "2147945552"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MadiLockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".MadiLock" ascii //weight: 3
        $x_1_2 = "README_TO_RECOVER_FILES!!!.txt" ascii //weight: 1
        $x_1_3 = "Files were encrypted and stolen. Pay to decrypt and delete stolen copies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

