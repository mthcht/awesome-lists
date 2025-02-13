rule Ransom_Win32_ElbeeCrypt_MFP_2147836572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ElbeeCrypt.MFP!MTB"
        threat_id = "2147836572"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ElbeeCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "elbeecrypt-key" ascii //weight: 1
        $x_1_2 = "DECRYPT_YOUR_FILES" ascii //weight: 1
        $x_1_3 = "ELBEECRYPT" ascii //weight: 1
        $x_1_4 = "Targeted extensions:" ascii //weight: 1
        $x_1_5 = "Root directories" ascii //weight: 1
        $x_1_6 = "Key fingerprint" ascii //weight: 1
        $x_1_7 = "your personal files were locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

