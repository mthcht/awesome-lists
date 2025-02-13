rule Trojan_Win32_Gatoodit_A_2147621289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatoodit.A"
        threat_id = "2147621289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatoodit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 bd 01 00 00 e8 ?? ?? ff ff 66 89 45 ee 6a 10 8d 45 ec 50 53 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {68 5c 11 00 00 e8 ?? ?? ff ff 66 89 45 ee 6a 10 8d 45 ec 50 53 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 f8 80 7c 02 ff 2e 75 d7}  //weight: 1, accuracy: High
        $x_1_4 = "echo Set WshShell = WScript.CreateObject (^\"WScript.Shell^\") >> C:\\1.vbs" ascii //weight: 1
        $x_1_5 = "echo WshShell.Run(^\"c:\\file.exe^\") >> C:\\1.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

