rule Trojan_Win32_Oyester_B_2147953900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyester.B!MTB"
        threat_id = "2147953900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyester"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "drive.usercontent.google.com/download?id=" ascii //weight: 1
        $x_1_2 = "&export=download&authuser=" ascii //weight: 1
        $x_1_3 = "HttpSendRequestA" ascii //weight: 1
        $x_1_4 = "schtasks.exe /Create" wide //weight: 1
        $x_1_5 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

