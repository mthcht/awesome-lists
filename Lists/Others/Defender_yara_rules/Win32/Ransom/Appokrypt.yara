rule Ransom_Win32_Appokrypt_A_2147716516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Appokrypt.A"
        threat_id = "2147716516"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Appokrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "2. 1-2 encrypted files (please dont send files bigger than 1 MB)" ascii //weight: 1
        $x_1_2 = {33 ff 33 f6 eb 06 8d 9b 00 00 00 00 8b 86 ?? ?? ?? ?? 50 8d 8c 24 ?? ?? 00 00 51 ff ?? 85 c0 74 05 bf 01 00 00 00 83 c6 04 83 fe 34 72 de 85 ff}  //weight: 1, accuracy: Low
        $x_1_3 = "recoveryhelp@bk.ru" ascii //weight: 1
        $x_1_4 = "decryptionservice@mail.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

