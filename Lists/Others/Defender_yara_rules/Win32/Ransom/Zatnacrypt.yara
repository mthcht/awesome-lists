rule Ransom_Win32_Zatnacrypt_A_2147708558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zatnacrypt.A"
        threat_id = "2147708558"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zatnacrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "supersecretpass" ascii //weight: 1
        $x_1_2 = ".vscrypt" ascii //weight: 1
        $x_1_3 = ":\\vsworkdir" ascii //weight: 1
        $x_1_4 = "*.pdf" ascii //weight: 1
        $x_1_5 = "\\shantazh.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

