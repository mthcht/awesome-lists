rule Trojan_Win64_PrairieWiper_A_2147944438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PrairieWiper.A"
        threat_id = "2147944438"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PrairieWiper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Make system unbootable by wiping critical OS files" ascii //weight: 1
        $x_1_2 = "Restart system after completion" ascii //weight: 1
        $x_1_3 = "Number of overwrite passes (1-7)" ascii //weight: 1
        $x_1_4 = "DESTRUCTION MODE: Targeting system drive only" ascii //weight: 1
        $x_1_5 = "WARNING: Wipe incomplete for %s: %d of %d files wiped (%.2f%%)" ascii //weight: 1
        $x_1_6 = "[PHASE 1] Destroying partition structures..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

