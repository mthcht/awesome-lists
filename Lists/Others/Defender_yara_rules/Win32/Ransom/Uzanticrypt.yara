rule Ransom_Win32_Uzanticrypt_PAA_2147798227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Uzanticrypt.PAA!MTB"
        threat_id = "2147798227"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Uzanticrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableTaskMgr" wide //weight: 1
        $x_1_2 = "HOW_TO_DECYPHER_FILES" wide //weight: 1
        $x_1_3 = "Drop Encrypted file for test decryption proof" wide //weight: 1
        $x_1_4 = ".UZANTICRYPT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

