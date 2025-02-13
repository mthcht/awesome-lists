rule Ransom_Win32_Dexcrypt_2147725773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dexcrypt"
        threat_id = "2147725773"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 2e 2d 27 20 20 20 20 20 20 27 2d 2e 0d 0a 20 20 2f 20 20 20 20 20 20 20 20 20 20 20 20 5c 20 0d 0a 20 7c 20 20 20 20 20 20 20 20 20 20 20 20 20 20 7c 0d 0a 20 7c 2c 20 20 2e 2d 2e 20 20 2e 2d 2e 20 20 2c 7c 0d 0a 20 7c 20 29 28 5f 5f 2f 20 20 5c 5f 5f 29 28 20 7c 0d 0a 20 7c 2f 20 20 20 20 20 2f 5c 20 20 20 20 20 5c 7c 0d 0a 20 28 5f 20 20 20 20 20 5e 5e 20 20 20 20 20 5f 29 0d 0a 20 20 5c 5f 5f 7c 49 49 49 49 49 49 7c 5f 5f 2f 0d 0a 20 20 20 7c 20 5c 49 49 49 49 49 49 2f 20 7c 0d 0a 20 20 20 5c 20 20 20 20 20 20 20 20 20 20 2f 0d 0a 20 20 20 20}  //weight: 2, accuracy: High
        $x_2_2 = "yao mi ma gei 30 yuan jia qq 2055965068" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

