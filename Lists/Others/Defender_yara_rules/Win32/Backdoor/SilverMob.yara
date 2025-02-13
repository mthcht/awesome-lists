rule Backdoor_Win32_SilverMob_A_2147724641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/SilverMob.A!dha"
        threat_id = "2147724641"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "SilverMob"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {b2 c0 50 51 c6 44 24 0c [0-5] c6 44 24 0e ?? c6 44 24 0f ?? c6 44 24 11 ?? c6 44 24 12 ?? c6 44 24 14 ?? c6 44 24 15 ?? c6 44 24 16 [0-5] c6 44 24 18 ?? c6 44 24 19 ?? c6 44 24 1a ?? c6 44 24 1b ?? e8 (?? ?? ?? ??|?? ?? ?? ?? 83)}  //weight: 20, accuracy: Low
        $x_10_2 = {33 d2 8a 91 ?? ?? ?? ?? ff 24 95 ?? ?? ?? ?? 8b 44 24 08 50 e8 ?? ?? 00 00 83 c4 04 c3}  //weight: 10, accuracy: Low
        $x_1_3 = "ping 127.0.0.1 -n 3" wide //weight: 1
        $x_1_4 = "2.02" wide //weight: 1
        $x_1_5 = "%s%s%s \"%s > %s 2>&1\"" wide //weight: 1
        $x_1_6 = "\" goto loop" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

