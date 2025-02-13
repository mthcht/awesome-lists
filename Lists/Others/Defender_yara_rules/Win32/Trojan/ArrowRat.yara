rule Trojan_Win32_ArrowRat_CAJ_2147842130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArrowRat.CAJ!MTB"
        threat_id = "2147842130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArrowRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 8d f8 fe ?? ?? 8a 95 f8 ?? ?? ?? 88 94 0d fc ?? ?? ?? 8b 85 f8 ?? ?? ?? 99 f7 7d 14 8b 85 f8 ?? ?? ?? 8b 4d 10 8a 14 11 88 94 05 ec fd ?? ?? eb}  //weight: 5, accuracy: Low
        $x_5_2 = {89 8d ec fe ?? ?? 8b 8d ec ?? ?? ?? 0f b6 94 0d fc ?? ?? ?? 8b 45 08 03 85 f0 ?? ?? ?? 0f b6 08 33 ca 8b 55 08 03 95 f0 ?? ?? ?? 88 0a e9}  //weight: 5, accuracy: Low
        $x_1_3 = "InstallUtil.exe" wide //weight: 1
        $x_1_4 = "SetThreadContext" ascii //weight: 1
        $x_1_5 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

