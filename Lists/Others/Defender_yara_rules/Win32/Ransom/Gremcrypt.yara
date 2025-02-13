rule Ransom_Win32_Gremcrypt_A_2147717147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gremcrypt.A"
        threat_id = "2147717147"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gremcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Cryptor\\trunk\\Libs\\Synopse\\SynCrypto.pas" wide //weight: 2
        $x_1_2 = "For obtaining decryption software, please, contact: %s" wide //weight: 1
        $x_1_3 = "encrypted_readme.txt" wide //weight: 1
        $x_1_4 = "encrypted_list.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Gremcrypt_A_2147717152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gremcrypt.A!!Gremcrypt.gen!A"
        threat_id = "2147717152"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gremcrypt"
        severity = "Critical"
        info = "Gremcrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Cryptor\\trunk\\Libs\\Synopse\\SynCrypto.pas" wide //weight: 2
        $x_1_2 = "For obtaining decryption software, please, contact: %s" wide //weight: 1
        $x_1_3 = "encrypted_readme.txt" wide //weight: 1
        $x_1_4 = "encrypted_list.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

