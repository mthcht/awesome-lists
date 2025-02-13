rule Worm_Win32_Wahrecks_A_2147637860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wahrecks.A"
        threat_id = "2147637860"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wahrecks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 83 f8 03 74 0c 66 83 f8 04 74 06 66 83 f8 02 75 5c}  //weight: 1, accuracy: High
        $x_1_2 = "shell\\open\\Command=/RECYCLER.{645FF040-5081-101B-9F08-00AA002F954E}" ascii //weight: 1
        $x_1_3 = {57 53 57 48 41 43 4b 45 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

