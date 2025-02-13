rule Trojan_Win32_Tocimob_A_2147681651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tocimob.gen!A"
        threat_id = "2147681651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tocimob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 3d 15 24 40 00 42 54 43 4d 0f 84 0a 01 00 00 81 3d 15 24 40 00 4c 54 43 4d 0f 84 23 02 00 00 81 3d 15 24 40 00 42 4f 54 48}  //weight: 2, accuracy: High
        $x_1_2 = "u/usft_ext.txt" ascii //weight: 1
        $x_1_3 = "u/miner.txt" ascii //weight: 1
        $x_1_4 = {70 74 68 72 65 61 64 47 43 32 2e 74 78 74 00 68 74 74 70 3a 2f 2f [0-20] 2e 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

