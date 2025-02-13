rule Ransom_Win32_Schuhcrypt_A_2147711665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Schuhcrypt.A"
        threat_id = "2147711665"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Schuhcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\LockFish" ascii //weight: 1
        $x_1_2 = "\\fileencrypt.exe" ascii //weight: 1
        $x_1_3 = ".fishing" ascii //weight: 1
        $x_1_4 = "/add.php?prvkey=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

