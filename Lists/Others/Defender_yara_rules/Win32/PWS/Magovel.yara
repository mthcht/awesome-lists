rule PWS_Win32_Magovel_A_2147625554_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Magovel.A"
        threat_id = "2147625554"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Magovel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 3a ff 33 55 f8 e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 df}  //weight: 1, accuracy: Low
        $x_1_2 = {66 83 f8 03 74 06 66 83 f8 04 75 53 6a 32}  //weight: 1, accuracy: High
        $x_1_3 = {26 76 65 72 3d 04 00 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

