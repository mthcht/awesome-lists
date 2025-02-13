rule TrojanSpy_Win32_Tinukebot_2147725031_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tinukebot.gen!bit"
        threat_id = "2147725031"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinukebot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "info|%d|%d|%d|%d|%s|%s|%d|%d" ascii //weight: 1
        $x_1_2 = {25 73 5c 25 73 5c 25 73 5c 25 73 2e 69 6e 69 [0-48] 4d 6f 7a 69 6c 6c 61}  //weight: 1, accuracy: Low
        $x_1_3 = {62 69 6e 7c 69 6e 74 33 32 [0-48] 00 62 69 6e 7c 69 6e 74 36 34}  //weight: 1, accuracy: Low
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-48] 64 6c 6c 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {00 69 6e 6a 65 63 74 73 00 [0-48] 46 69 72 65 66 6f 78 [0-48] 43 68 72 6f 6d 65}  //weight: 1, accuracy: Low
        $x_1_6 = "user_pref(\"layers.acceleration.disabled\", true);" ascii //weight: 1
        $x_1_7 = "--no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

