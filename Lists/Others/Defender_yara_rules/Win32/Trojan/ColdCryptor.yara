rule Trojan_Win32_ColdCryptor_A_2147847318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ColdCryptor.A"
        threat_id = "2147847318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ColdCryptor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ColdCryptor" wide //weight: 1
        $x_1_2 = "coldcryptor.exe" ascii //weight: 1
        $x_1_3 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_4 = "EncryptFile" ascii //weight: 1
        $x_1_5 = "Encrypted:" wide //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

