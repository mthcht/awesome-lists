rule Backdoor_Win32_Sogu_A_2147720579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sogu.A!dha"
        threat_id = "2147720579"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sogu"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d fc 5a 7e 09 b8 cc cc cc cc ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 02 0f b6 4d ?? 0f b6 55 ?? 03 ca 0f b6 55 ?? 03 ca 0f b6 55 ?? 03 ca 33 c1}  //weight: 1, accuracy: Low
        $x_1_3 = "SafeSvc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

