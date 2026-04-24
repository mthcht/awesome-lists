rule DoS_Python_WprAblate_A_2147967645_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Python/WprAblate.A!dha"
        threat_id = "2147967645"
        type = "DoS"
        platform = "Python: Python scripts"
        family = "WprAblate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-p MicrosoftDefenderDeleteProxy" wide //weight: 1
        $x_1_2 = "-p SentinelOneDeleteProxy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

