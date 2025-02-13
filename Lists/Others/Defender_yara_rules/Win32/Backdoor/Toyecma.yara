rule Backdoor_Win32_Toyecma_A_2147708076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Toyecma.A!dha"
        threat_id = "2147708076"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Toyecma"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 57 49 4e 5d 00 00 00 5b 43 54 52 4c 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = "[%02d/%02d/%d %02d:%02d:%02d] (%s)" ascii //weight: 1
        $x_1_3 = "tvtsvc is running" ascii //weight: 1
        $x_1_4 = {0f b6 59 01 88 1c 08 0f b6 19 fe cb 88 5c 37 01 83 c6 02 83 c1 02 3b f2 7e ?? 8b ?? ?? 8b ?? ?? 8b c3 25 01 00 00 80 79 ?? 48 83 c8 fe 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

