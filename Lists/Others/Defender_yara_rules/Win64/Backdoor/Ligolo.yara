rule Backdoor_Win64_Ligolo_B_2147775569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Ligolo.B!dha"
        threat_id = "2147775569"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Ligolo"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-relayserver" wide //weight: 1
        $x_1_2 = "-skipverify" wide //weight: 1
        $x_1_3 = "-autorestart" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

