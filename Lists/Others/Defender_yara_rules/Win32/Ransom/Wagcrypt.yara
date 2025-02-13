rule Ransom_Win32_Wagcrypt_A_2147719531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wagcrypt.A"
        threat_id = "2147719531"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wagcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Welcome to my Ransomware!" ascii //weight: 1
        $x_1_2 = "In order to have relationship with us, and pay the ransom;" ascii //weight: 1
        $x_1_3 = "zXz.html" ascii //weight: 1
        $x_2_4 = {b8 ab aa aa 2a f7 ef c1 fa 02 8b fa c1 ef 1f 03 fa}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Wagcrypt_A_2147719560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wagcrypt.A!!Wagcrypt.gen!A"
        threat_id = "2147719560"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wagcrypt"
        severity = "Critical"
        info = "Wagcrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Welcome to my Ransomware!" ascii //weight: 1
        $x_1_2 = "In order to have relationship with us, and pay the ransom;" ascii //weight: 1
        $x_1_3 = "zXz.html" ascii //weight: 1
        $x_2_4 = {b8 ab aa aa 2a f7 ef c1 fa 02 8b fa c1 ef 1f 03 fa}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

