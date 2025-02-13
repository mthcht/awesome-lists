rule Backdoor_Win32_Uclinu_A_2147688521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Uclinu.A"
        threat_id = "2147688521"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Uclinu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 55 55 53 55 55 51 55 ff 15 ?? ?? ?? ?? a0 14 56 40 00 b9 ff 01 00 00 88 84 24 98 02 00 00 33 c0 8d bc 24 99 02 00 00 8b 54 24 2c f3 ab 66 8b 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 66 ab aa 66 89 8c 24 98 0a 00 00 b9 ff 03 00 00 33 c0 8d bc 24 9a 0a 00 00 f3 ab 88 1d 00 56 40 00 66 ab ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 7c 24 50 33 c0 f3 a5 66 a5 b9 73 00 00 00 8d bc 24 8a 00 00 00 f3 ab 6a 00 66 ab ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "\\tasks\\taskmgr.exe" wide //weight: 1
        $x_1_4 = "www.ilscnu.org.findhere.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

