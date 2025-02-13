rule Ransom_MSIL_SpriseCrypt_A_2147710838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SpriseCrypt.A!bit"
        threat_id = "2147710838"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpriseCrypt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If your files is important just email us to discuss the price and how to decrypt your files" wide //weight: 1
        $x_1_2 = "We accept just BITCOIN if you dont know what it is just google it" wide //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_4 = "\\Encrypted_Files.Notepad" wide //weight: 1
        $x_1_5 = {2a 00 24 00 2a 00 [0-4] 2a 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2a 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 00 70 00 68 00 70 00 ?? ?? 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 ?? ?? 70 00 63 00 6e 00 61 00 6d 00 65 00 ?? ?? 50 00 4f 00 53 00 54 00 ?? ?? 61 00 65 00 73 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

