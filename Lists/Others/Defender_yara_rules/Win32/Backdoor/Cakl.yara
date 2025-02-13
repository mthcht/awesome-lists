rule Backdoor_Win32_Cakl_B_2147623747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cakl.gen!B"
        threat_id = "2147623747"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cakl"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff ff ff ff 06 00 00 00 44 65 6e 65 73 65}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff ff ff 06 00 00 00 50 6f 72 74 4e 6f}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff ff ff 06 00 00 00 4b 75 72 62 61 6e}  //weight: 1, accuracy: High
        $x_1_4 = {ff ff ff ff 08 00 00 00 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: High
        $x_1_5 = "msnmsgr.exe" ascii //weight: 1
        $x_1_6 = "Ftp/IE/Firefox/Outlook Passwords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

