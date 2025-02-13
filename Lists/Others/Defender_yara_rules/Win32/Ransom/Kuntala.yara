rule Ransom_Win32_Kuntala_2147729496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kuntala"
        threat_id = "2147729496"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuntala"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "!_HOW_RECOVERY_FILES_!.txt" wide //weight: 2
        $x_2_2 = "[ ALL YOUR FILES HAVE BEEN ENCRYPTED! ]" wide //weight: 2
        $x_2_3 = "Your files are NOT damaged! Your files are modified only. This modification is reversible." wide //weight: 2
        $x_2_4 = "The only 1 way to decrypt your files is to receive the decryption program." wide //weight: 2
        $x_2_5 = "To believe, you can give us up to 3 files that we decrypt for free." wide //weight: 2
        $x_2_6 = "Files should not be important to you! (databases, backups, large excel sheets, etc.)" wide //weight: 2
        $x_4_7 = ">>>>>>>>>>>>>>>>>>>>>>>>>>>> NOT_OPEN LOCKER <<<<<<<<<<<<<<<<<<<<<<<<<<<<" wide //weight: 4
        $x_4_8 = "To receive the decryption program write to email: notopen@countermail.com" wide //weight: 4
        $x_4_9 = "If we do not respond within 24 hours, write to the email: not.open@mailfence.com" wide //weight: 4
        $x_4_10 = ".[notopen@countermail.com].NOT_OPEN" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

