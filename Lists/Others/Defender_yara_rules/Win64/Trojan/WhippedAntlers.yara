rule Trojan_Win64_WhippedAntlers_A_2147971575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WhippedAntlers.A!dha"
        threat_id = "2147971575"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WhippedAntlers"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c1 48 8b 4c 24 ?? 0f b6 09 33 c8 8b c1 48 8b 4c 24 ?? 88 01 8b 44 24 24 ff c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

