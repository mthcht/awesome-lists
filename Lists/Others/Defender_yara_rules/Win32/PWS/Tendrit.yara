rule PWS_Win32_Tendrit_B_2147678266_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tendrit.B"
        threat_id = "2147678266"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tendrit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 8c 05 ?? ?? ?? ?? 40 83 f8 40 72 ea e8}  //weight: 2, accuracy: Low
        $x_1_2 = "css.ashx?" ascii //weight: 1
        $x_1_3 = "policyref?" ascii //weight: 1
        $x_1_4 = "2K3.%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

