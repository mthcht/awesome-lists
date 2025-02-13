rule Trojan_Win32_Darkeye_MA_2147822279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkeye.MA!MTB"
        threat_id = "2147822279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1c 36 32 b6 a4 f3 8c 42 b7 43 08 7c 79 1d 30 6a}  //weight: 1, accuracy: High
        $x_1_2 = "4C3enmesh" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "Demonisms" ascii //weight: 1
        $x_1_5 = "barbatif lectrifierons" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

