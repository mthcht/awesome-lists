rule Ransom_Win32_Stylcrypt_A_2147726360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stylcrypt.A"
        threat_id = "2147726360"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stylcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hello, friend, Please read the following" ascii //weight: 1
        $x_1_2 = "Your file has been locked, please do not close the system, or modify the extension name" ascii //weight: 1
        $x_1_3 = "GOATGOATGOATGOATGOATGOATGOATGOATGOATGOATGOATGOAT" ascii //weight: 1
        $x_2_4 = "*.Stinger" ascii //weight: 2
        $x_2_5 = "E-mail:hackcwand@protonmail.com" ascii //weight: 2
        $x_2_6 = "About .Stinger unlocking instructions.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

