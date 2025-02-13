rule Ransom_Win32_Jexcrypt_A_2147708557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jexcrypt.A"
        threat_id = "2147708557"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jexcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".xejyyk" wide //weight: 1
        $x_1_2 = "Warning Wrong Wallet Address" wide //weight: 1
        $x_1_3 = "Impossible to find the transaction" wide //weight: 1
        $x_1_4 = "TTime." wide //weight: 1
        $x_1_5 = "mkw" wide //weight: 1
        $x_1_6 = "work\\ml1\\Release" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

