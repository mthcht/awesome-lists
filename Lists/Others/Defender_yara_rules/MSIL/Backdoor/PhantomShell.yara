rule Backdoor_MSIL_PhantomShell_B_2147848178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/PhantomShell.B"
        threat_id = "2147848178"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 75 6d 61 6e 32 5f 61 73 70 78 01 09 61 2d 7a 41 2d 5a 30 2d 39 01 00 01 09 61 2d 7a 41 2d 5a 30 2d 39}  //weight: 1, accuracy: Low
        $x_1_2 = "X-siLock-Comment" wide //weight: 1
        $x_1_3 = "x-siLock-Step1" wide //weight: 1
        $x_1_4 = {4d 4f 56 45 69 74 2e 44 4d 5a 2e 43 6f 72 65 2e 44 61 74 61 01 09 61 2d 7a 41 2d 5a 30 2d 39 01 00 01 09 61 2d 7a 41 2d 5a 30 2d 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

