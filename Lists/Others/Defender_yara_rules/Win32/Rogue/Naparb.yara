rule Rogue_Win32_Naparb_168546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Naparb"
        threat_id = "168546"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Naparb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 68 79 20 63 61 6e 60 74 20 49 20 72 65 6d 6f 76 65 20 74 68 65 20 76 69 72 75 73 65 73 20 00 ff ff ff ff 90 00 00 00 64 65 74 65 63 74 73 3f 00}  //weight: 3, accuracy: High
        $x_2_2 = {54 72 6f 6a 61 6e 2e 48 6f 6f 62 6c 6f 6e 67 2e 41 00}  //weight: 2, accuracy: High
        $x_2_3 = "Your computer is compromised by hackers, adware, malware and worms!" ascii //weight: 2
        $x_1_4 = "has detected some serious threats to your computer!" ascii //weight: 1
        $x_1_5 = "one of the best antiviruses today?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

