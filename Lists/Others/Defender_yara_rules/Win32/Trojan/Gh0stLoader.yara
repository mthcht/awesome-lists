rule Trojan_Win32_Gh0stLoader_A_2147789124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gh0stLoader.A!dha"
        threat_id = "2147789124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gh0stLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 8d 9c 39}  //weight: 1, accuracy: High
        $x_1_2 = {42 09 9e 5f}  //weight: 1, accuracy: High
        $x_1_3 = {e2 9a 5a f5}  //weight: 1, accuracy: High
        $x_1_4 = {1b c2 10 3b}  //weight: 1, accuracy: High
        $x_1_5 = {71 a7 e8 fe}  //weight: 1, accuracy: High
        $x_1_6 = {81 8f f0 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

