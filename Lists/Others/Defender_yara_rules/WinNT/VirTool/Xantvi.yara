rule VirTool_WinNT_Xantvi_A_2147601376_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Xantvi.gen!A"
        threat_id = "2147601376"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Xantvi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 08 56 8b 70 28 6a 00 ff 15 ?? ?? 01 00 8d 4e 50 ff 15 ?? ?? 01 00 5e c2 10 00}  //weight: 5, accuracy: Low
        $x_5_2 = {01 00 8b 48 08 c1 e1 02 51 ff 30 6a 00 ff 15 ?? ?? 01 00 85 c0 a3 ?? ?? 01 00 75 06 b8 01 00 00 c0 c3 03 00 a1}  //weight: 5, accuracy: Low
        $x_10_3 = {50 56 56 56 8d 45 d4 50 68 3f 00 0f 00 8d 45 08 50 c7 45 d4 18 00 00 00 89 75 d8 c7 45 e0 40 02 00 00 89 75 e4 89 75 e8 ff 15 ?? ?? 01 00 85 c0 75 50 8b 45 0c 89 45 f0 8d 50 02 66 8b 08 40}  //weight: 10, accuracy: Low
        $x_13_4 = {8d 45 e8 50 ff 15 ?? ?? 01 00 8b 45 0c 89 45 f0 8d 45 f0 50 8d 45 d0 50 68 ff 0f 1f 00 8d 45 08 50 89 5d 08 89 5d f4 ff 15 ?? ?? 01 00 53 ff 75 08 ff 15 ?? ?? 01 00 47 8d 34 bd ?? ?? 01 00 39 1e 75 ad}  //weight: 13, accuracy: Low
        $x_1_5 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "ZwTerminateProcess" ascii //weight: 1
        $x_1_7 = "ZwOpenProcess" ascii //weight: 1
        $x_1_8 = "HalMakeBeep" ascii //weight: 1
        $x_1_9 = "\\avp.exe" ascii //weight: 1
        $x_1_10 = "\\kav.exe" ascii //weight: 1
        $x_1_11 = "\\wincom32.sys" ascii //weight: 1
        $x_1_12 = "\\Device\\Beep" ascii //weight: 1
        $x_1_13 = "\\mpfirewall.sys" ascii //weight: 1
        $x_1_14 = "\\avgw.exe" ascii //weight: 1
        $x_1_15 = "\\msmpeng.exe" ascii //weight: 1
        $x_1_16 = "\\navw32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 12 of ($x_1_*))) or
            ((2 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_13_*) and 4 of ($x_1_*))) or
            ((1 of ($x_13_*) and 1 of ($x_5_*))) or
            ((1 of ($x_13_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

