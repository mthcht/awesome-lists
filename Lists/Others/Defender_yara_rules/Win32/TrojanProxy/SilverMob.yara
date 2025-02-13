rule TrojanProxy_Win32_SilverMob_A_2147724640_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/SilverMob.A!dha"
        threat_id = "2147724640"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "SilverMob"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {b2 c0 50 51 c6 44 24 0c [0-5] c6 44 24 0e ?? c6 44 24 0f ?? c6 44 24 11 ?? c6 44 24 12 ?? c6 44 24 14 ?? c6 44 24 15 ?? c6 44 24 16 [0-5] c6 44 24 18 ?? c6 44 24 19 ?? c6 44 24 1a ?? c6 44 24 1b ?? e8 (?? ?? ?? ??|?? ?? ?? ?? 83)}  //weight: 20, accuracy: Low
        $x_2_2 = {66 81 fe 34 80 75 ?? 6a 00 8d 44 24 ?? 68 27 80 00 00 50 e8 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = "netsh.exe firewall add " wide //weight: 2
        $x_2_4 = "netsh.exe advfirewall firewall add" wide //weight: 2
        $x_1_5 = {69 67 66 78 [0-8] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

