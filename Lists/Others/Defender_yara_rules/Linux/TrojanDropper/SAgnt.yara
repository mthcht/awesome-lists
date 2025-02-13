rule TrojanDropper_Linux_SAgnt_A_2147828130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Linux/SAgnt.A!xp"
        threat_id = "2147828130"
        type = "TrojanDropper"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 49 c7 c0 a0 10 40 00 48 c7 c1 b0 10 40 00 48 c7 c7 80 0a 40 00}  //weight: 3, accuracy: High
        $x_1_2 = {b8 c8 16 60 00 55 48 2d c8 16 60 00 48 c1 f8 03 48 89 e5 48 89 c2 48 c1 ea 3f 48 01 d0 48 89 c6 48 d1 fe}  //weight: 1, accuracy: High
        $x_1_3 = "Good luck, Ebola-chan" ascii //weight: 1
        $x_1_4 = "%s %s -O- 2>/dev/null" ascii //weight: 1
        $x_1_5 = "UDP Flooder" ascii //weight: 1
        $x_1_6 = "Starting Flood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

