rule HackTool_Win32_SmbAgent_J_2147743299_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SmbAgent.J!ibt"
        threat_id = "2147743299"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SmbAgent"
        severity = "High"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 20 bd 01 00 00 6f 05 00 00 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {06 19 91 06 18 91 20 00 01 00 00 5a 58 06 19 91 20 00 00 01 00 5a 58 0b 07 1a 58 8d 0b 00 00 01}  //weight: 1, accuracy: High
        $x_1_3 = {3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 70 64 62 00}  //weight: 1, accuracy: Low
        $x_1_4 = "PingCastle.Scanners" ascii //weight: 1
        $x_1_5 = "ReadSmbResponse" ascii //weight: 1
        $x_1_6 = "m17sc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

