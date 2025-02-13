rule DoS_Win64_ActionWipe_B_2147905634_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win64/ActionWipe.B!dha"
        threat_id = "2147905634"
        type = "DoS"
        platform = "Win64: Windows 64-bit platform"
        family = "ActionWipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {33 c0 8e d0 bc 00 7c fb 50 07 50 1f fc be 5d 7c 33 c9 41 81 f9 00 02 74 24 b4 43 b0 00 cd 13 fe}  //weight: 100, accuracy: High
        $x_100_2 = "PhysicalDrive%d  Write MBR %s" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

