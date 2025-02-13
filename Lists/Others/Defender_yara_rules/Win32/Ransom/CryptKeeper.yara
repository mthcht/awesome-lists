rule Ransom_Win32_CryptKeeper_A_2147685410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptKeeper.A"
        threat_id = "2147685410"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptKeeper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Keeper ID could not be sent." ascii //weight: 1
        $x_1_2 = "data will be decrypted in backround mode." ascii //weight: 1
        $x_1_3 = {25 59 2d 25 6d 2d 25 64 20 5b 25 58 5d 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 65 2e 70 68 70 3f 69 64 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

