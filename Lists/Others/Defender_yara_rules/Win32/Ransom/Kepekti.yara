rule Ransom_Win32_Kepekti_A_2147723754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kepekti.A"
        threat_id = "2147723754"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kepekti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encryption Complete" wide //weight: 1
        $x_1_2 = "TO UNLOCK THIS COMPUTER YOU ARE OBLIGED TO PAY" wide //weight: 1
        $x_1_3 = "Localbitcoins.com" wide //weight: 1
        $x_2_4 = "Builder Ransom.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

