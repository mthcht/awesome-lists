rule Trojan_Win32_Ddkong_A_2147728416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ddkong.A"
        threat_id = "2147728416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ddkong"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_2 = "%s \"%s\",Rundll32Call" ascii //weight: 1
        $x_1_3 = "NewCopyOutOfUAC" ascii //weight: 1
        $x_1_4 = {80 34 38 c3 40 3b 46 04 72}  //weight: 1, accuracy: High
        $x_1_5 = {ff ff 59 59 68 [0-64] 50 c6 45 ?? 4b ff 35 f0 72 00 10 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 6e c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 44 c6 45 ?? 6c c6 45 ?? 6c c6 45 ?? 43 c6 45 ?? 6d c6 45 ?? 64 c6 45 ?? 41 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

