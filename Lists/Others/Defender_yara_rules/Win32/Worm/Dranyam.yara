rule Worm_Win32_Dranyam_A_2147601331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dranyam.A"
        threat_id = "2147601331"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dranyam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "\\Temp\\+ Marc\\Quarantine\\exe\\projects\\Project MMA\\exe\\v3 with Antidote\\mma.vbp" wide //weight: 6
        $x_2_2 = "shell\\Explore\\Command=MarcMaynard.exe /e" wide //weight: 2
        $x_2_3 = "autorun.inf" wide //weight: 2
        $x_2_4 = "    |  Marc Maynard was here!   |" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

