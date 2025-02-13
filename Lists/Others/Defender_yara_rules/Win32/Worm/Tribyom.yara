rule Worm_Win32_Tribyom_2147619826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Tribyom"
        threat_id = "2147619826"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Tribyom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Allows error reporting for services and applictions running in non-standard environments." wide //weight: 1
        $x_1_2 = "\\Services\\htuad\\" wide //weight: 1
        $x_1_3 = "\\Services\\stuad\\" wide //weight: 1
        $x_3_4 = "Cyzpait.inf" wide //weight: 3
        $x_3_5 = "LOGY`WSJX[EVI`QMGVSWSJX`[MRHS[W`GYVVIRXZIVWMSR`VYR`" wide //weight: 3
        $x_1_6 = "autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

