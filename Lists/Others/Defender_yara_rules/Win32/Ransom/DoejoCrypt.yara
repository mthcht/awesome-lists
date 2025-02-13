rule Ransom_Win32_DoejoCrypt_A_2147777392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DoejoCrypt.A"
        threat_id = "2147777392"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DoejoCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your file has been encrypted!" ascii //weight: 1
        $x_1_2 = "If you want to decrypt, please contact us." ascii //weight: 1
        $x_1_3 = "And please send me the following hash!" ascii //weight: 1
        $x_1_4 = "dear!!!" ascii //weight: 1
        $x_1_5 = "create rsa error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

