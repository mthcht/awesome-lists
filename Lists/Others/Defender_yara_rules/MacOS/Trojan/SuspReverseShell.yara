rule Trojan_MacOS_SuspReverseShell_A_2147944300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspReverseShell.A"
        threat_id = "2147944300"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspReverseShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "python3 -c" wide //weight: 1
        $x_1_2 = "import subprocess" wide //weight: 1
        $x_1_3 = {73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 50 00 6f 00 70 00 65 00 6e 00 28 00 5b 00 27 00 6e 00 63 00 27 00 2c 00 [0-48] 2c 00 20 00 73 00 74 00 72 00 28 00 [0-48] 29 00 5d 00 2c 00 20 00 73 00 74 00 64 00 69 00 6e 00 3d 00 73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 50 00 49 00 50 00 45 00 2c 00 20 00 73 00 74 00 64 00 6f 00 75 00 74 00 3d 00 73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 50 00 49 00 50 00 45 00 2c 00 20 00 74 00 65 00 78 00 74 00 3d 00 54 00 72 00 75 00 65 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 50 00 6f 00 70 00 65 00 6e 00 28 00 5b 00 [0-48] 5d 00 2c 00 20 00 73 00 74 00 64 00 69 00 6e 00 3d 00 [0-48] 2e 00 73 00 74 00 64 00 6f 00 75 00 74 00 2c 00 20 00 73 00 74 00 64 00 6f 00 75 00 74 00 3d 00 [0-48] 2e 00 73 00 74 00 64 00 69 00 6e 00 2c 00 20 00 73 00 74 00 64 00 65 00 72 00 72 00 3d 00 [0-48] 2e 00 73 00 74 00 64 00 69 00 6e 00 2c 00 20 00 74 00 65 00 78 00 74 00 3d 00 54 00 72 00 75 00 65 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = ".wait()" wide //weight: 1
        $x_1_6 = ".kill()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

