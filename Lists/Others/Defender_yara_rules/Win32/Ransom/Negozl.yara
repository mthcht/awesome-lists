rule Ransom_Win32_Negozl_A_2147716123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Negozl.A"
        threat_id = "2147716123"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Negozl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".evil" ascii //weight: 1
        $x_1_2 = "All your attempts to restore files on their own, lead to the loss of the possibility of recovery and we are not going to help you.<" ascii //weight: 1
        $x_1_3 = "NegozI Rnsm" ascii //weight: 1
        $x_1_4 = "RemindMe_Ransom" ascii //weight: 1
        $x_1_5 = "\\DECRYPT_YOUR_FILES.HTML" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

