rule Trojan_Win64_VagrantTorpedo_B_2147956525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VagrantTorpedo.B!dha"
        threat_id = "2147956525"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VagrantTorpedo"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 2c 45 36 16 66 14 7b 1c 6e 0f 62 42 21 40 2e 40 2f 5b 7b 19 7c 5c 2e 5b 35 15 7c 12 32 76 39 6a 4a 27 48 2c 49 67}  //weight: 1, accuracy: High
        $x_1_2 = {6a 30 49 bd 43 56 77 e8 f9 7b da a8 44 9f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

