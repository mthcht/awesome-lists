rule HackTool_Win32_keylogger_2147621731_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/keylogger"
        threat_id = "2147621731"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "keylogger"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HexLogger" ascii //weight: 1
        $x_1_2 = "http://kurdojan.tr.gg/" ascii //weight: 1
        $x_1_3 = {73 00 65 00 6e 00 64 00 75 00 73 00 69 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 00 65 00 6e 00 64 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {4d 00 61 00 69 00 6c 00 20 00 4f 00 72 00 67 00 61 00 6e 00 74 00 69 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

