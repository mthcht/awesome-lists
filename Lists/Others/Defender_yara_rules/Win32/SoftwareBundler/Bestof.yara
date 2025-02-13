rule SoftwareBundler_Win32_Bestof_214131_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Bestof"
        threat_id = "214131"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Bestof"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "exe.ac_tobm_putes" ascii //weight: 2
        $x_2_2 = "ezitenoma/ogsart" ascii //weight: 2
        $x_2_3 = "moc.sutaicsafsuibocemrym" ascii //weight: 2
        $x_1_4 = "//VERYSILENT" ascii //weight: 1
        $x_1_5 = "{tmp}\\inst.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

