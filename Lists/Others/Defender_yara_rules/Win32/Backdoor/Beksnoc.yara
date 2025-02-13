rule Backdoor_Win32_Beksnoc_A_2147647254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beksnoc.A"
        threat_id = "2147647254"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beksnoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 c0 74 13 3d e3 00 00 00 74 0c 0f b6 04 ?? 35 e3 00 00 00 88 04}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 18 8b 55 fc 0f b6 54 15 e9 01 da 31 d0 88 45 fb 80 7d fb 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 f8 01 74 5e c6 45 ?? 26 c6 45 ?? 6c c6 45 ?? 70 c6 45 ?? 25 c6 45 ?? 75 c6 45 ?? 3d c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {80 7f 08 4d 74 0d 80 7f 09 5a 74 07 31 c0}  //weight: 1, accuracy: High
        $x_1_5 = {c6 40 01 53 c6 40 02 3a c6 40 03 53 c6 40 04 4d c6 40 05 53 c6 40 06 53 c6 40 07 5f c6 40 08 42 c6 40 09 55 c6 40 0a 47}  //weight: 1, accuracy: High
        $x_1_6 = {6a 53 6a 4f 6a 46 68 ?? ?? ?? ?? 8d 85 4c f7 ff ff 50 e8}  //weight: 1, accuracy: Low
        $x_1_7 = {c6 07 00 6a 3a 89 f8 40 50 e8}  //weight: 1, accuracy: High
        $x_1_8 = {01 fa 31 d0 88 45 ff 80 7d ff 00 74 0b}  //weight: 1, accuracy: High
        $x_1_9 = "&id=%s&o=%s&v=%s" ascii //weight: 1
        $x_1_10 = "q=%c&id=%s&o=%s&%c=%s" ascii //weight: 1
        $x_1_11 = "q=%c&id=%s&%c=%s&%c=%s" ascii //weight: 1
        $x_1_12 = "q=%c&%s=%s&%c=%s&%c=%s" ascii //weight: 1
        $x_1_13 = "#UPLOADED#" ascii //weight: 1
        $x_1_14 = {23 21 40 50 4f 53 00}  //weight: 1, accuracy: High
        $x_1_15 = "RunDll32.exe BeTwinProxyVS.dll,Register" ascii //weight: 1
        $x_1_16 = "XTP[KM]: WGR e=%u" ascii //weight: 1
        $x_1_17 = "msrdp#v" ascii //weight: 1
        $x_1_18 = "\\termsrv.dll_bkk" ascii //weight: 1
        $x_1_19 = {09 c0 75 31 c6 ?? 45 c6 ?? 01 53 c6 ?? 02 3a c6 ?? 03 53 c6 ?? 04 4d c6 ?? 05 53 c6 ?? 06 53 c6 ?? 07 5f c6 ?? 08 42 c6 ?? 09 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Beksnoc_A_2147658938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beksnoc.gen!A"
        threat_id = "2147658938"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beksnoc"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 81 fa e3 00 00 00 74 17 8b 45 ?? 03 45 ?? 0f be 08 81 f1 e3 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 42 05 83 f8 2b 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 ec 3d 0d 00 00 8b 0d ?? ?? ?? ?? 83 e9 40 f7 d9 1b c9}  //weight: 1, accuracy: Low
        $x_1_4 = {45 53 43 4b 3a 25 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

