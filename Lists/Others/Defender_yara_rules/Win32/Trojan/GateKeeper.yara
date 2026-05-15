rule Trojan_Win32_GateKeeper_LVM_2147969384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GateKeeper.LVM!MTB"
        threat_id = "2147969384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GateKeeper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 00 00 79 00 00 00 70 00 00 00 65 00 00 00 72 00 00 00 64 00 00 00 62 00 00 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 00 00 00 73 00 00 00 70 00 00 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "MainWindowTitle" ascii //weight: 1
        $x_1_4 = "GetProcesses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

