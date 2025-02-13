rule TrojanDropper_Win32_Detnat_A_2147595443_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Detnat.gen.dr!A"
        threat_id = "2147595443"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Detnat"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a 00 41 67 65 6e 74 25 6c 64 00 00 00 00 2e 72 73 72 63 00 00 00 2e 64 61 74 61 00 00 00 2e 65 78 65 00 00 00 00 5c 00 00 00 2a 2e 2a 00 43 3a 5c 00 25 73 25 73 25 64 2e 65 78 65 00 00 6e 65 74 72 75 6e 00 00 6e 65 74 64 61 74 2e 74 6d 70 00 00 64 65 6c 70 68 69 00 00 5c 20 00 00 25 73 2e 65 78 65 00 00 53 56 43 48 4f 53 54 00 53 56 43 48 30 53 54 00 43 3a 5c 52 65 63 79 63 6c 65 64 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

