rule Trojan_Win64_CircuitMantis_A_2147981308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CircuitMantis.A!dha"
        threat_id = "2147981308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CircuitMantis"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Local\\Temp\\chromechip.log\" | iex" wide //weight: 1
        $x_1_2 = "\\AppData\\Local\\Temp\\chromechip.log' | iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

