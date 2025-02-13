rule Ransom_Win32_AmigUCrypt_2147754991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AmigUCrypt!MTB"
        threat_id = "2147754991"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AmigUCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Amigo-U2" wide //weight: 1
        $x_1_2 = "!!!READ_IT!!!.txt" wide //weight: 1
        $x_1_3 = "ALL YOUR DATA WAS ENCRYPTED" wide //weight: 1
        $x_1_4 = "Encryptor.exe" ascii //weight: 1
        $x_1_5 = "<CreateCrypter>" ascii //weight: 1
        $x_1_6 = "<EncryptFile>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

