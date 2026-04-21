rule Backdoor_Win64_SeaMonkey_A_2147967368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/SeaMonkey.A!dha"
        threat_id = "2147967368"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "SeaMonkey"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/agent/poll?token=" wide //weight: 1
        $x_1_2 = "Failed to upload file to server, status:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

