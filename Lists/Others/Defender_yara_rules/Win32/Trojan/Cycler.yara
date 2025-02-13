rule Trojan_Win32_Cycler_MA_2147819717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cycler.MA!MTB"
        threat_id = "2147819717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cycler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 04 02 88 01 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 44 01 f7 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 d2 6a 0c 59 f7 f1 a3 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
        $x_1_2 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

