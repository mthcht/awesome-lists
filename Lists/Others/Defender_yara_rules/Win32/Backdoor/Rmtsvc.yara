rule Backdoor_Win32_Rmtsvc_C_2147718014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rmtsvc.C!bit"
        threat_id = "2147718014"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rmtsvc"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 69 6e 64 69 70 00 00 73 76 72 70 6f 72 74 00 73 65 74 74 69 6e 67 00 73 74 6f 70 00 00 00 00 72 75 6e}  //weight: 1, accuracy: High
        $x_1_2 = "[upload] ip=%s - %s upload %s" ascii //weight: 1
        $x_1_3 = {73 65 6e 64 69 6e 67 [0-16] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii //weight: 1
        $x_1_5 = {6a 40 68 00 10 00 00 53 6a 00 55 ff 15 ?? ?? ?? ?? 8b f0 85 f6 0f 84}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 00 6a 00 56 53 6a 00 6a 00 55 ff 15 ?? ?? ?? ?? 8b d8 85 db 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

