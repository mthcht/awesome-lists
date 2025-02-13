rule Ransom_Win32_Kasacrypt_A_2147716137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kasacrypt.A"
        threat_id = "2147716137"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasacrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".korrektor" ascii //weight: 1
        $x_2_2 = "korrektorfile\\shell\\open\\command" ascii //weight: 2
        $x_2_3 = "c:\\look.jpg" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

