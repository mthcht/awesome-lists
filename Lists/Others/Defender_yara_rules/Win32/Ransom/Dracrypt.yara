rule Ransom_Win32_Dracrypt_A_2147726340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dracrypt.A"
        threat_id = "2147726340"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dracrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".desucrpt" wide //weight: 2
        $x_2_2 = "C:\\Users\\delta\\source\\repos\\desuCrypt\\Release\\desuCrypt.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

