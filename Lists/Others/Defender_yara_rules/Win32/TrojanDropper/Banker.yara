rule TrojanDropper_Win32_Banker_C_2147639957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Banker.C"
        threat_id = "2147639957"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 61 6e 65 73 74 65 73 2e 63 6f 6d 2e 62 72 [0-5] 3e 3e [0-32] 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_2 = {63 72 65 64 69 63 61 72 64 2e 63 6f 6d 2e 62 72 [0-5] 3e 3e [0-32] 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_3 = {70 61 67 61 6d 65 6e 74 6f 64 69 67 69 74 61 6c 2e 63 6f 6d 2e 62 72 [0-5] 3e 3e [0-32] 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_4 = {70 61 79 70 61 6c 2e 63 6f 6d 2e 62 72 [0-5] 3e 3e [0-32] 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_5 = {62 72 61 64 65 73 63 6f 2e 63 6f 6d 2e 62 72 [0-5] 3e 3e [0-32] 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_6 = {62 61 6e 72 69 73 75 6c 2e 63 6f 6d 2e 62 72 [0-5] 3e 3e [0-32] 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_7 = {73 65 72 61 73 61 65 78 70 65 72 69 61 6e 2e 63 6f 6d 2e 62 72 [0-5] 3e 3e [0-32] 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_8 = {61 6d 65 72 69 63 61 6e 65 78 70 72 65 73 73 2e 63 6f 6d 2e 62 72 [0-5] 3e 3e [0-32] 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_9 = {69 74 61 75 2e 63 6f 6d 2e 62 72 [0-5] 3e 3e [0-32] 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_10 = {68 6f 74 6d 61 69 6c 2e 63 6f 6d 2e 62 72 [0-5] 3e 3e [0-32] 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Banker_E_2147645540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Banker.E"
        threat_id = "2147645540"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h@#@t@t#p:@//vi@su@#ali#zaca@o.b#@lo@g.b#@r/" ascii //weight: 1
        $x_1_2 = "#r@#e@@g add \"H@#KEY_C@URRE@NT_USER\\S@OF#@TW@ARE\\Micr@o#soft\\Wi@n#@do@ws\\Cur@re@#ntVersi@on@\\R#@u#n\" /#v s@#y@@#@s#@y@ /d \"#@C@#:\\" ascii //weight: 1
        $x_1_3 = "#@C@#:\\@sy#s@@#tea@#m\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Banker_O_2147732007_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Banker.O"
        threat_id = "2147732007"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Time_ProgressBar" ascii //weight: 1
        $x_1_2 = "*\\AC:\\Users\\Admin\\Desktop\\other_cr\\R_PE\\2201\\_CLC.vbp" wide //weight: 1
        $x_1_3 = "EXP_CPFIX" wide //weight: 1
        $x_1_4 = "TIPOFDAY.TXT" wide //weight: 1
        $x_1_5 = "TimeRemain.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

