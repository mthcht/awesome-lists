rule PWS_Win32_Zakahic_A_2147654821_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zakahic.A"
        threat_id = "2147654821"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zakahic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {80 f9 4f 7f 05 80 c1 30 eb 03 80 e9 30 88 0a 42}  //weight: 10, accuracy: High
        $x_1_2 = {43 49 43 60 [0-8] 5e 34 3c 3c}  //weight: 1, accuracy: Low
        $x_1_3 = "5<5=5>D3<95>D^5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

