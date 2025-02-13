rule Worm_Win32_Perkesh_A_2147616757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Perkesh.gen!A"
        threat_id = "2147616757"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 f4 68 c0 5d 00 71 8d 83 84 00 00 00 50 c6 45 0b 01 ff 15 74 50 00 71 50 ff 15 78 51 00 71}  //weight: 2, accuracy: High
        $x_1_2 = {45 78 70 6c 6f 69 74 00 52 45 53}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 25 73 2e 69 6e 66 [0-4] 61 75 74 6f 72 75 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "%s\\open\\%s %s,%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Perkesh_B_2147620107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Perkesh.gen!B"
        threat_id = "2147620107"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 0d 8a 0c 18 f6 d1 88 0c 18 40 3b c6 7c f3}  //weight: 2, accuracy: High
        $x_2_2 = {3c 05 75 1e 33 c9 8a cc 84 c9 75 07 68 24 65 40 00 eb 05 68 18 65 40 00 ff 15}  //weight: 2, accuracy: High
        $x_1_3 = "urlm0n.dll" ascii //weight: 1
        $x_1_4 = "\\drivers\\Beep.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

