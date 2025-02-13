rule Trojan_Win32_Hewilnep_SA_2147760540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hewilnep.SA!MTB"
        threat_id = "2147760540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hewilnep"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 42 00 4b 00 48 00 4e 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {40 00 18 00 01 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 6d 00 73 00 69 00 6e 00 73 00 74 00 78 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\WINDOWS\\WINHELP.INI" wide //weight: 1
        $x_1_4 = "C:\\WINDOWS\\Help\\.HLP" wide //weight: 1
        $x_1_5 = "shutdown /s /f /t 0" wide //weight: 1
        $x_1_6 = "runinjectcmd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

