rule Trojan_Win32_Rokum_A_2147751736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rokum.A!dha"
        threat_id = "2147751736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rokum"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3e 6a 12 5f 23 87 54 12 96 a3 dc 56 0c 69 ad 1e}  //weight: 1, accuracy: High
        $x_1_2 = {45 40 dc a3 fe 05 2e ba 01 83 d9 fa 36 da 7f 98}  //weight: 1, accuracy: High
        $x_1_3 = {cd ab dc a3 fe 29 34 b1 08 93 df a1 fa 7d 36 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

