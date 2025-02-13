rule Worm_Win32_Radoom_A_2147620603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Radoom.A"
        threat_id = "2147620603"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Radoom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 72 6f 74 65 63 74 6f 72 2e 65 78 65 00 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_2 = {5b 61 75 74 6f 72 75 6e 5d [0-4] 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 25 73}  //weight: 10, accuracy: Low
        $x_5_3 = "send $nick CHANNEL-RULES" ascii //weight: 5
        $x_1_4 = "Doomsday Has Come" ascii //weight: 1
        $x_1_5 = "YOU ARE iNFECTED BY RAVO_5002" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

