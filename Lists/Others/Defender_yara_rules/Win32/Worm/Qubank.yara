rule Worm_Win32_Qubank_A_2147726649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Qubank.A!bit"
        threat_id = "2147726649"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Qubank"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Facebook Spreaded Successfuly" ascii //weight: 1
        $x_1_2 = "QuBank - Infected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

