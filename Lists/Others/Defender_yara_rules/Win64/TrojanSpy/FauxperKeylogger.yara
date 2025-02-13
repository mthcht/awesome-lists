rule TrojanSpy_Win64_FauxperKeylogger_2147726588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/FauxperKeylogger"
        threat_id = "2147726588"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "FauxperKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LLoggerFile = svhost.exe" ascii //weight: 1
        $x_1_2 = "LUploaderFile = spoolsvc.exe" ascii //weight: 1
        $x_1_3 = "LCoreFile = explorers.exe" ascii //weight: 1
        $x_1_4 = "Keybd hook: %s" ascii //weight: 1
        $x_1_5 = "WindowSpy.ahk or AU3_Spy.exe" ascii //weight: 1
        $x_1_6 = "CoreFileList = %RCoreFile%|%LLoggerFile%|%LUploaderFile%|%LCoreFile%" ascii //weight: 1
        $x_1_7 = "pwb.silent := true" ascii //weight: 1
        $x_1_8 = "pwb.document.all.Submit.Click()" ascii //weight: 1
        $x_1_9 = "SVI = System Volume Information" ascii //weight: 1
        $x_1_10 = {43 00 6f 00 72 00 65 00 20 00 3d 00 20 00 4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 [0-32] 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}  //weight: 1, accuracy: Low
        $x_1_11 = {43 6f 72 65 20 3d 20 4b 61 73 70 65 72 73 6b 79 [0-32] 53 65 63 75 72 69 74 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

