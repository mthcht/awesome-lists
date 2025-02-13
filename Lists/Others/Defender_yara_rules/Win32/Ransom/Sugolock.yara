rule Ransom_Win32_Sugolock_2147729987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sugolock"
        threat_id = "2147729987"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sugolock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "38"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "All your files locked!" ascii //weight: 2
        $x_2_2 = "Your personal email: 5btc@protonmail.com" ascii //weight: 2
        $x_2_3 = "You have to pay some bitcoins to unlock your files!" ascii //weight: 2
        $x_2_4 = "DECRYPT.html" ascii //weight: 2
        $x_2_5 = "5btc@protonmail.com" ascii //weight: 2
        $x_2_6 = "Don't try decrypt your files!" ascii //weight: 2
        $x_2_7 = "If you try to unlock your files, you may lose access to them!" ascii //weight: 2
        $x_2_8 = "No one can guarantee you a 100% unlock except us!" ascii //weight: 2
        $x_30_9 = {54 68 65 4a 75 73 74 47 75 73 [0-24] 5c 47 55 53 63 72 79 70 74 6f 6c 6f 63 6b 65 72 20 2d 20 75 70 64 61 74 65 5c 52 65 6c 65 61 73 65 5c 6c 6f 63 6b 65 72 2e 70 64 62}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

