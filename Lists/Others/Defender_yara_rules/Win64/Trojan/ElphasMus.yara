rule Trojan_Win64_ElphasMus_A_2147967364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ElphasMus.A!dha"
        threat_id = "2147967364"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ElphasMus"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{\"client_id\":\"%s\",\"computer_name\":\"%s\",\"username\":\"%s\",\"domain\":\"%s\"}" ascii //weight: 1
        $x_1_2 = "{\"client_id\":\"%s\",\"status\":\"%s\",\"error_code\":\"%s\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

