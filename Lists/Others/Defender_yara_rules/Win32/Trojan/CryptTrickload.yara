rule Trojan_Win32_CryptTrickload_B_2147769327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptTrickload.B!MTB"
        threat_id = "2147769327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptTrickload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 70 68 70 3f 73 69 3d [0-16] 26 6b 6f 3d [0-16] 26 63 76 3d [0-32] 2c 20 22 66 61 6c 73 65 22 29 3b}  //weight: 1, accuracy: Low
        $x_1_2 = "@@Windows Defender::%ProgramFiles%\\Windows Defender\\MsMpeng.exe@@" ascii //weight: 1
        $x_1_3 = {2e 6f 70 65 6e 28 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f [0-32] 2f [0-16] 2f [0-21] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_4 = ".ExecQuery(\"Select * from Win32_NetworkAdapterConfiguration Where IPEnabled=TRUE\");" ascii //weight: 1
        $x_1_5 = ".ExecQuery(\"Select DomainRole from Win32_ComputerSystem\");" ascii //weight: 1
        $x_1_6 = ".ExecQuery(\"Select * from AntiVirusProduct\");" ascii //weight: 1
        $x_1_7 = ".ExpandEnvironmentStrings(\"%TEMP%\");" ascii //weight: 1
        $x_1_8 = {2e 53 6c 65 65 70 28 22 [0-16] 22 29 3b}  //weight: 1, accuracy: Low
        $x_1_9 = "wscript  /e:JScript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

