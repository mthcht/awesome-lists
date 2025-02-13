rule PWS_Win32_Ceekat_A_2147599264_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ceekat.gen!A"
        threat_id = "2147599264"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceekat"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 00 6a fc (53|56) e8 ?? ?? ?? ?? 6a 00 8d 45 ?? 50 6a 04 (53 56|56 53) e8 ?? ?? ?? ?? 81 (33|36) ?? ?? ?? ?? 6a 00 (53|56) e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 02 6a 00 6a fc (53|56) e8 ?? ?? ?? ?? 6a 00 8d 45 ?? 50 6a 04 8d 45 ?? 50 (53|56) e8 ?? ?? ?? ?? 81 75 ?? ?? ?? ?? ?? 6a 00 (53|56) e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Ceekat_B_2147605001_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ceekat.gen!B"
        threat_id = "2147605001"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceekat"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_2 = "action=getyxlogin&u=" ascii //weight: 1
        $x_1_3 = "action=getupos&mac=" ascii //weight: 1
        $x_1_4 = "action=getmac" ascii //weight: 1
        $x_1_5 = "W0W.exe" ascii //weight: 1
        $x_1_6 = "wow.exe" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
        $x_1_8 = "Explorer.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

