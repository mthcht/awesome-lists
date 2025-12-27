rule Trojan_Win32_PossibleProcessInjection_A_2147949937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PossibleProcessInjection.A"
        threat_id = "2147949937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PossibleProcessInjection"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "notepad.exe" wide //weight: 1
        $n_10_2 = ".txt" wide //weight: -10
        $n_10_3 = ".log" wide //weight: -10
        $n_10_4 = ".readme" wide //weight: -10
        $n_10_5 = ".ini" wide //weight: -10
        $n_10_6 = ".cfg." wide //weight: -10
        $n_10_7 = ".conf" wide //weight: -10
        $n_10_8 = ".config" wide //weight: -10
        $n_10_9 = ".resx" wide //weight: -10
        $n_10_10 = ".resmoncfg" wide //weight: -10
        $n_10_11 = ".csv" wide //weight: -10
        $n_10_12 = ".tsv" wide //weight: -10
        $n_10_13 = ".yaml" wide //weight: -10
        $n_10_14 = ".json" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

