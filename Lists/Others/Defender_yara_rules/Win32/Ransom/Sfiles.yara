rule Ransom_Win32_Sfiles_B_2147820193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sfiles.B!dha"
        threat_id = "2147820193"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfiles"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "->Confidential files, Passports, HR directories, Employees personal info" ascii //weight: 1
        $x_1_2 = "->Detailed company information, Accountant files" ascii //weight: 1
        $x_1_3 = "->Financial documents, Commercial info" ascii //weight: 1
        $x_1_4 = "%ws EncryptionStage1 begin" ascii //weight: 1
        $x_1_5 = "%ws EncryptionStage2 begin, totally %d files in queue" ascii //weight: 1
        $x_1_6 = "WaitForHours() : gogogo" ascii //weight: 1
        $x_1_7 = "! cynet ransom protection(don't delete)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

