rule Worm_Win32_Caphaw_A_2147682741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Caphaw.A"
        threat_id = "2147682741"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/hijackcfg/plugins/plugin" ascii //weight: 2
        $x_1_2 = "folders:%d;;;spread:%d" ascii //weight: 1
        $x_2_3 = "spreadmutex" ascii //weight: 2
        $x_1_4 = {83 e8 02 74 2e 48 74 0c 48 75 ?? c7 47 ?? 6e 65 74 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

