rule Backdoor_Win64_SignJoin_A_2147888309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/SignJoin.A"
        threat_id = "2147888309"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "SignJoin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "My bolls - my rules" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

