rule PWS_Win32_Briba_A_2147660611_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Briba.A"
        threat_id = "2147660611"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Briba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "c0d0so0" ascii //weight: 10
        $x_1_2 = "MSMAPI32.SRG" ascii //weight: 1
        $x_1_3 = {50 4f 53 54 [0-16] 69 6e 64 65 78 25 30 2e 39 64 2e 61 73 70}  //weight: 1, accuracy: Low
        $x_2_4 = {2b c2 d1 e8 03 c2 c1 e8 1d 69 c0 00 ca 9a 3b}  //weight: 2, accuracy: High
        $x_2_5 = {80 f9 3a 74 0f 80 f9 20 74 0a 40 3b c7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

