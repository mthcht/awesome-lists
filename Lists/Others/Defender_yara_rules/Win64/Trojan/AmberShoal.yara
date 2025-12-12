rule Trojan_Win64_AmberShoal_A_2147959335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AmberShoal.A"
        threat_id = "2147959335"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AmberShoal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 44 24 48 4c c6 44 24 49 8b}  //weight: 2, accuracy: High
        $x_1_2 = {0f be 00 83 f8 78 75}  //weight: 1, accuracy: High
        $x_1_3 = {78 78 78 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

