rule Virus_Win32_Glacid_A_2147656796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Glacid.A"
        threat_id = "2147656796"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Glacid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\iglicd64.dl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

