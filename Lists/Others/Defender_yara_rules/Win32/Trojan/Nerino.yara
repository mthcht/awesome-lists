rule Trojan_Win32_Nerino_A_2147727481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nerino.A!bit"
        threat_id = "2147727481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nerino"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iNerino BOTNET" ascii //weight: 1
        $x_1_2 = "SaveScreenshotToFile" ascii //weight: 1
        $x_1_3 = "schtasks.exe /create /tn System\\SystemUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

