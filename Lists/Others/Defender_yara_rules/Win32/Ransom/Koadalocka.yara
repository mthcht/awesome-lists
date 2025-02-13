rule Ransom_Win32_Koadalocka_B_2147805811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Koadalocka.B"
        threat_id = "2147805811"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Koadalocka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Bitcoin to following address" wide //weight: 2
        $x_2_2 = "important files are encrypted" wide //weight: 2
        $x_2_3 = "Copying notPetya" wide //weight: 2
        $x_2_4 = "deletejournal /D C:" wide //weight: 2
        $x_2_5 = "your important files are encrypted" wide //weight: 2
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
        $x_1_7 = "ATT&CK3valuat10n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

