rule Ransom_Win32_Jest_B_2147753025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jest.B!MSR"
        threat_id = "2147753025"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jest"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptedfiles.eco" wide //weight: 1
        $x_1_2 = "ProgramData\\note.ini" wide //weight: 1
        $x_1_3 = "Decryptor.lnk" wide //weight: 1
        $x_1_4 = "Paid!, Decoing files..q=how+to+buy+bitcoin" wide //weight: 1
        $x_1_5 = "scripts\\jest.vbs" wide //weight: 1
        $x_1_6 = "q=how+to+buy+bitcoin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

