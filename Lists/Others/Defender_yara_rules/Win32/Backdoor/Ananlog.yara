rule Backdoor_Win32_Ananlog_A_2147713072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ananlog.A"
        threat_id = "2147713072"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ananlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "last_scr+" wide //weight: 1
        $x_1_2 = "last_upl+picdir_" wide //weight: 1
        $x_1_3 = "\\0.keyl-" wide //weight: 1
        $x_1_4 = "rem_old_" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Ananlog_A_2147713072_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ananlog.A"
        threat_id = "2147713072"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ananlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GraphicsModuleExtra" wide //weight: 1
        $x_1_2 = "new_upd.exe" wide //weight: 1
        $x_1_3 = "\\Teilc\\" wide //weight: 1
        $x_1_4 = "/LIVE/HOST.php" wide //weight: 1
        $x_1_5 = "signed.php" wide //weight: 1
        $x_1_6 = "timerkeyl_" wide //weight: 1
        $x_1_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-10] 2e 00 69 00 72 00 2f 00 4c 00 49 00 56 00 45 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_8 = "<!-- Hosting24 Analytics Code -->" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

