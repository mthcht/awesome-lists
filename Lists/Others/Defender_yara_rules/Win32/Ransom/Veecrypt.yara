rule Ransom_Win32_Veecrypt_A_2147721259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Veecrypt.A"
        threat_id = "2147721259"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Veecrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vCrypt1" wide //weight: 1
        $x_1_2 = "fns-service@pochta.com" wide //weight: 1
        $x_1_3 = "%IHKJOIY8348923ggROihIjoi" wide //weight: 1
        $x_1_4 = {44 00 3a 00 5c 00 00 00 43 00 3a 00 5c 00 00 00 45 00 3a 00 5c 00 00 00 46 00 3a 00 5c 00 00 00 4f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

