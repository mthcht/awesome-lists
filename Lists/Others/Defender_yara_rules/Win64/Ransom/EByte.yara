rule Ransom_Win64_EByte_AUJ_2147931956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/EByte.AUJ!MTB"
        threat_id = "2147931956"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "EByte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decryption Instructions.txt" ascii //weight: 1
        $x_1_2 = "locker-1737916344749291200" ascii //weight: 1
        $x_1_3 = "EByte-Rware/encryption.EncryptFile" ascii //weight: 1
        $x_1_4 = "main.setWallpaper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

