rule Trojan_Win32_Dexter_EC_2147892108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexter.EC!MTB"
        threat_id = "2147892108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Now all the evasion techniques you decided will be used" ascii //weight: 1
        $x_1_2 = "If some of them detect to be under analysis your program will be no launched." ascii //weight: 1
        $x_1_3 = "Checking process of malware analysis tool" ascii //weight: 1
        $x_1_4 = "ollydbg.exe" ascii //weight: 1
        $x_1_5 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_6 = "tcpview.exe" ascii //weight: 1
        $x_1_7 = "VBoxMouse.sys" ascii //weight: 1
        $x_1_8 = "VBoxGuest.sys" ascii //weight: 1
        $x_1_9 = "VBoxSF.sys" ascii //weight: 1
        $x_1_10 = "SELECT * FROM Win32_PhysicalMemory" ascii //weight: 1
        $x_1_11 = "SELECT * FROM Win32_MemoryDevice" ascii //weight: 1
        $x_1_12 = "SELECT * FROM Win32_MemoryArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

