rule TrojanClicker_Win32_Pulick_B_2147687802_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Pulick.B"
        threat_id = "2147687802"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Pulick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "XRXeXfXeXrXeXrX:X" ascii //weight: 1
        $x_1_2 = {63 6c 69 63 6b 2e 68 74 6d 6c [0-4] 6a 73 [0-4] 67 6f 6f 67 6c 65 [0-4] 66 61 63 65 62 6f 6f 6b [0-4] 61 64 73}  //weight: 1, accuracy: Low
        $x_1_3 = {78 68 61 6d 73 74 65 72 [0-4] 64 6f 75 62 6c 65 69 6d 70 [0-4] 65 72 6f 2d 61 64 76 [0-4] 65 78 6f 63 6c 69 63 6b}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c0 40 50 6a 08 50 6a 07 50 6a 06 50 6a 05 50 6a 04 50 6a 03 50 6a 02 50 50 50 6a 00 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8}  //weight: 1, accuracy: Low
        $x_1_5 = {33 ff 89 7d fc 57 68 ?? ?? ?? ?? 8d 4d 10 e8 ?? ?? ?? ?? 83 ce ff 3b c6 0f 8f ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 8d 4d 10 e8 ?? ?? ?? ?? 3b c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Pulick_C_2147689197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Pulick.C"
        threat_id = "2147689197"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Pulick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "window.onbeforeunload=null;window.showModalDialog=null;window.confirm=null;window.open=null;document.body.onclick=null;" ascii //weight: 3
        $x_3_2 = "XRXeXfXeXrXeXrX:X" ascii //weight: 3
        $x_1_3 = "m2rXfX" ascii //weight: 1
        $x_1_4 = "click.html" ascii //weight: 1
        $x_1_5 = "doubleimp" ascii //weight: 1
        $x_1_6 = "m2rf.com" ascii //weight: 1
        $x_1_7 = "fagt.com" ascii //weight: 1
        $x_1_8 = "exoclick" ascii //weight: 1
        $x_1_9 = "ero-adv" ascii //weight: 1
        $x_1_10 = "adultadworld" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

