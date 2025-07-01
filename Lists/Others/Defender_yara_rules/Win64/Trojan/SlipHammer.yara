rule Trojan_Win64_SlipHammer_A_2147945130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SlipHammer.A!dha"
        threat_id = "2147945130"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SlipHammer"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "has been filled with spaces to match its original size." wide //weight: 1
        $x_1_2 = "Warning: File size mismatch after filling! Expected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

