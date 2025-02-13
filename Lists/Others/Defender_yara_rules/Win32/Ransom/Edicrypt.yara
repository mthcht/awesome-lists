rule Ransom_Win32_Edicrypt_A_2147717149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Edicrypt.A"
        threat_id = "2147717149"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Edicrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AES_Encrypt" ascii //weight: 1
        $x_1_2 = "EncryptText" ascii //weight: 1
        $x_1_3 = "Decrypt-Tool you can decrypt your files! If you don't pay" ascii //weight: 1
        $x_1_4 = "Key to decrypt: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Edicrypt_A_2147717153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Edicrypt.A!!Edicrypt.gen!A"
        threat_id = "2147717153"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Edicrypt"
        severity = "Critical"
        info = "Edicrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AES_Encrypt" ascii //weight: 1
        $x_1_2 = "EncryptText" ascii //weight: 1
        $x_1_3 = "Decrypt-Tool you can decrypt your files! If you don't pay" ascii //weight: 1
        $x_1_4 = "Key to decrypt: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

