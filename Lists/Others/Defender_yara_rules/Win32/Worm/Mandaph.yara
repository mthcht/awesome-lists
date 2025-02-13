rule Worm_Win32_Mandaph_A_2147608883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mandaph.A"
        threat_id = "2147608883"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mandaph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "104"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "http://dns-blabla.org/shl/" ascii //weight: 10
        $x_10_2 = "cftmon.exe" ascii //weight: 10
        $x_10_3 = "spools.exe" ascii //weight: 10
        $x_10_4 = "manda.php" ascii //weight: 10
        $x_10_5 = "logonui.exe" ascii //weight: 10
        $x_10_6 = "autorun.inf" ascii //weight: 10
        $x_10_7 = "\\drivers\\" ascii //weight: 10
        $x_1_8 = "data.php" ascii //weight: 1
        $x_1_9 = "vbs.php" ascii //weight: 1
        $x_1_10 = "ntuser" ascii //weight: 1
        $x_1_11 = "autoload" ascii //weight: 1
        $x_1_12 = "\\exefile\\shell\\open\\command\\" ascii //weight: 1
        $x_1_13 = "ShellExecute=autorun.exe" ascii //weight: 1
        $x_1_14 = "WinExec" ascii //weight: 1
        $x_10_15 = {53 b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed}  //weight: 10, accuracy: High
        $x_10_16 = {8b 45 fc 40 89 45 fc ff 75 08 ff 15 ?? ?? ?? ?? 39 45 fc 7d 16 8b 45 08 03 45 fc 0f be 00 33 45 0c 8b 4d 08 03 4d fc 88 01 eb d5}  //weight: 10, accuracy: Low
        $x_10_17 = {85 c0 75 0d 68 80 4f 12 00 ff 15 ?? ?? 83 00 eb 0b 68 10 27 00 00 ff 15 ?? ?? 83 00 e9 ?? ?? ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

