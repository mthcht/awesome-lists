rule Trojan_Win32_DarkTortilla_PA_2147926043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkTortilla.PA!MTB"
        threat_id = "2147926043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Release\\exebak.pdb" ascii //weight: 3
        $x_1_2 = {25 00 30 00 38 00 6c 00 58 00 2d 00 25 00 30 00 34 00 58 00 2d 00 25 00 30 00 34 00 78 00 2d 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 2d 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58}  //weight: 1, accuracy: High
        $x_1_3 = "RestartByRestartManager" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

