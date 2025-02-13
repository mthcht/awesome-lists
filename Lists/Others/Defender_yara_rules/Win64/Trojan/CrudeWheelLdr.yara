rule Trojan_Win64_CrudeWheelLdr_A_2147929827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CrudeWheelLdr.A!dha"
        threat_id = "2147929827"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CrudeWheelLdr"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 83 c5 0f 49 2b ff 4d 2b e7 49 c1 ee 04 0f 1f 80 ?? ?? ?? ?? 41 0f 10 34 1c 49 8d 34 1c 4c 8b c3 48 8b d6 48 8d 4d ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

