rule Ransom_Win32_Ascrirac_A_2147690206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ascrirac.A"
        threat_id = "2147690206"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ascrirac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rescan and decrypt all files" wide //weight: 1
        $x_1_2 = "Show encrypted files" wide //weight: 1
        $x_1_3 = "Payment instruction" wide //weight: 1
        $x_1_4 = "Check Payment" wide //weight: 1
        $x_1_5 = "Your payment is not received" wide //weight: 1
        $x_1_6 = "Your payment received, Now decrypt all files" wide //weight: 1
        $x_10_7 = {43 00 72 00 79 00 70 00 74 00 6f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

