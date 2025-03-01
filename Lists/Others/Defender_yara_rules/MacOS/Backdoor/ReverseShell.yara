rule Backdoor_MacOS_ReverseShell_A_2147934895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/ReverseShell.A"
        threat_id = "2147934895"
        type = "Backdoor"
        platform = "MacOS: "
        family = "ReverseShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 69 70 65 00 66 6f 72 6b 00 2f 62 69 6e 2f 73 68 00 73 68 00 65 78 65 63 6c 00 35 31 2e 38 39 2e 32 32 2e 31 34 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

