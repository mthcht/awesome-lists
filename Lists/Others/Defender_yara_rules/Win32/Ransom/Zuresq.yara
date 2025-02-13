rule Ransom_Win32_Zuresq_A_2147688675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zuresq.A"
        threat_id = "2147688675"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zuresq"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "been encrypted using an extremely secure and unbreakable algorit" ascii //weight: 1
        $x_1_2 = "Visit www.localbitcoins.com to find a seller in your area." ascii //weight: 1
        $x_1_3 = {5c 00 52 00 75 00 6e 00 00 15 46 00 69 00 6c 00 65 00 52 00 65 00 73 00 63 00 75 00 65 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5a 00 65 00 72 00 6f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 00 0f 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 00 11 2e 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 00 29 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 00 70 00 61 00 74 00 72 00 69 00 6f 00 74 00 65 00 2f 00 73 00 61 00 6e 00 73 00 76 00 69 00 6f 00 6c 00 65 00 6e 00 63 00 65 00 00 1b 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Zuresq_A_2147688675_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zuresq.A"
        threat_id = "2147688675"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zuresq"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {28 60 00 00 06 13 ?? 45 08 00 00 00 00 00 00 00 ?? ff ff ff ?? ff ff ff ?? ff ff ff ?? ff ff ff ?? ff ff ff ?? ff ff ff [0-128] 11 ?? 13 ?? 11 ?? 20 ?? ?? 00 00 28 60 00 00 06 30 ?? 18 45 01 00 00 00 f6 ff ff ff [0-16] 20 ?? ?? 00 00 28 60 00 00 06 2b 02 11 ?? 45 02 00 00 00 00 00 00 00 ?? ff ff ff de 34 75 4b 00 00 01 14 fe 03 11}  //weight: 3, accuracy: Low
        $x_3_2 = {28 60 00 00 06 13 06 45 08 00 00 00 00 00 00 00 ?? ff ff ff ?? ff ff ff ?? ff ff ff ?? ff ff ff ?? ff ff ff ?? ff ff ff ?? ff ff ff [0-6] 11 07 13 06 11 05 20}  //weight: 3, accuracy: Low
        $x_1_3 = "GetBitcoinAddress" ascii //weight: 1
        $x_1_4 = "UseBitcoinAddress" ascii //weight: 1
        $x_1_5 = "EncryptFiles" ascii //weight: 1
        $x_1_6 = "DecryptFiles" ascii //weight: 1
        $x_1_7 = "getPassword" ascii //weight: 1
        $x_1_8 = "dlDesktopFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

