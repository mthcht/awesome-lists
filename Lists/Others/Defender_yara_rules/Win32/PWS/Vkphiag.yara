rule PWS_Win32_Vkphiag_A_2147697336_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Vkphiag.A"
        threat_id = "2147697336"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Vkphiag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AlVXZFMUqyrnABp8ncuU" ascii //weight: 1
        $x_1_2 = "stub.photo" ascii //weight: 1
        $x_1_3 = {5f 65 6e 63 72 79 70 74 65 64 00 [0-32] 2e 65 78 65 [0-32] 68 74 74 70 3a 2f 2f [0-9] 2e [0-9] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

