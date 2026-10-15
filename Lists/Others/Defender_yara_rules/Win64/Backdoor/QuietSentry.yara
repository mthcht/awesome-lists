rule Backdoor_Win64_QuietSentry_D_2147980365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/QuietSentry.D!dha"
        threat_id = "2147980365"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "QuietSentry"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 57 4d 54 53 76 63 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_QuietSentry_E_2147980368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/QuietSentry.E!dha"
        threat_id = "2147980368"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "QuietSentry"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WMTPROBEOK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

