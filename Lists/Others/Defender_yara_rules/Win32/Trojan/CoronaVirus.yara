rule Trojan_Win32_CoronaVirus_V_2147751461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoronaVirus.V!MTB"
        threat_id = "2147751461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoronaVirus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c rd/s /q c:\\" wide //weight: 1
        $x_1_2 = "cmd /c REG DELETE HKLM\\Software\\ /f" wide //weight: 1
        $x_1_3 = "cmd /c rd/s /q d:\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

