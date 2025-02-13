rule Trojan_Win32_TravNet_MA_2147826869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TravNet.MA!MTB"
        threat_id = "2147826869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TravNet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 e3 73 c6 45 e4 76 c6 45 e5 63 c6 45 e6 68 c6 45 e7 6f c6 45 e8 73 c6 45 e9 74 c6 45 ea 2e c6 45 eb 74 c6 45 ec 78 c6 45 ed 74 c6 45 ee 00 6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 55 d4 52 ff 55}  //weight: 1, accuracy: High
        $x_1_2 = "RunDllEntry" ascii //weight: 1
        $x_1_3 = "tionCatcher" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

