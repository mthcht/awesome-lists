rule Backdoor_Win32_Usinec_A_2147651441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Usinec.A"
        threat_id = "2147651441"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Usinec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 ff d0 69 de ?? ?? 00 00 89 84 1d ?? ?? ff ff 89 bc 1d ?? ?? ff ff 89 bc 1d ?? ?? ff ff [0-16] 8d 45 fc 50 a1 ?? ?? ?? ?? 8b 00 b9 06 00 00 00 ba 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 68 1f 00 0f 00 53 a1 ?? ?? ?? ?? 8b 00 ff d0 a3 ?? ?? ?? ?? 83 3d 01 00 74 [0-9] 8b c6 b9 ?? ?? 00 00 8b 15 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Usinec_B_2147652872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Usinec.B"
        threat_id = "2147652872"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Usinec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 ff d0 69 de ?? ?? 00 00 89 84 1d ?? ?? ff ff 89 bc 1d ?? ?? ff ff 89 bc 1d ?? ?? ff ff 8d 45 fc 50 a1 ?? ?? ?? ?? 8b 00 b9 06 00 00 00 ba 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 75 c5}  //weight: 1, accuracy: High
        $x_1_3 = "i7\\3RD\\k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Usinec_D_2147655453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Usinec.D"
        threat_id = "2147655453"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Usinec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows NT\\CurrentVersion\\Winlogon\\Notify" ascii //weight: 1
        $x_1_2 = "Support USB3 Service" ascii //weight: 1
        $x_1_3 = "NEUSBw32.dll" ascii //weight: 1
        $x_1_4 = "USB3Sw32.dll" ascii //weight: 1
        $x_1_5 = "usbnaw32.dll" ascii //weight: 1
        $x_1_6 = "usbniw32.dll" ascii //weight: 1
        $x_1_7 = "{sys}\\itlsvc.dat" ascii //weight: 1
        $x_1_8 = "http://handjobheats.com/xgi-bin/q.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

