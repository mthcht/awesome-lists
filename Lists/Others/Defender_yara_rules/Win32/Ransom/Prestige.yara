rule Ransom_Win32_Prestige_B_2147833323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Prestige.B"
        threat_id = "2147833323"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Prestige"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 2d 2d 2d 2d 45 4e 44 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d 0a 00 00 00 ?? 00 50 00 72 00 65 00 73 00 74 00 69 00 67 00 65 00 2e 00 72 00 61 00 6e 00 75 00 73 00 6f 00 6d 00 65 00 77 00 61 00 72 00 65 00 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Prestige_SA_2147913038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Prestige.SA"
        threat_id = "2147913038"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Prestige"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Prestige.ranusomeware@Proton.me" wide //weight: 2
        $x_2_2 = "C:\\Windows\\System32\\reg.exe add HKCR\\enc\\shell\\open\\command /ve /t REG_SZ /d \"C:\\Windows\\Notepad.exe C:\\Users\\Publi" wide //weight: 2
        $x_1_3 = "To decrypt all the data, you will need to purchase our decryption software." wide //weight: 1
        $x_1_4 = "Contact us {}. In the letter, type your ID = {:X}." wide //weight: 1
        $x_1_5 = "- Do not try to decrypt your data using third party software, it may cause permanent data loss." wide //weight: 1
        $x_1_6 = "- Do not modify or rename encrypted files. You will lose them." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

