rule TrojanSpy_Win64_GoStealer_A_2147922787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/GoStealer.A!ldr"
        threat_id = "2147922787"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "GoStealer"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b 45 eb 8b 55 88 4c 89 8d e3 fe ff ?? 89 95 ef fe ff ff 4c 01 4d e2 89 8d 7c fe ff ff 49 89 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

