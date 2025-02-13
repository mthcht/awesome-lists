rule TrojanSpy_Win32_Stioldaat_STA_2147781463_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stioldaat.STA"
        threat_id = "2147781463"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stioldaat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 00 55 00 52 00 4c 00 20 00 3d 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2e 00 63 00 6f 00 6d 00 [0-16] 2f 00 75 00 70 00 6c 00 64 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = "*.doc;*.pdf;*.ppt;*.dot;*.xl;" wide //weight: 1
        $x_1_3 = "_HTTP_UPLOAD ( $URL & $UUID , $ARETURN " wide //weight: 1
        $x_1_4 = "FILEWRITE ( $HFILE , \"start /b \"\"\"\" cmd /min /c del \"\"%~f0\"\"& Taskkill /IM cmd.exe /F&exit /b\" & @CRLF )" wide //weight: 1
        $x_1_5 = {52 00 55 00 4e 00 20 00 28 00 20 00 22 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 6d 00 69 00 6e 00 20 00 [0-8] 2e 00 62 00 61 00 74 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

