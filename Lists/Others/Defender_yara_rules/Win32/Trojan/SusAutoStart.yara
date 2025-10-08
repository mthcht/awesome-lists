rule Trojan_Win32_SusAutoStart_A_2147954140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusAutoStart.A"
        threat_id = "2147954140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusAutoStart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c echo" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "readme." ascii //weight: 1
        $x_1_4 = "notepad.exe" ascii //weight: 1
        $x_1_5 = "Netwalker_Ransomware_" ascii //weight: 1
        $x_1_6 = "MountLocker." ascii //weight: 1
        $x_1_7 = "Darkside." ascii //weight: 1
        $x_1_8 = "Sodinokibi." ascii //weight: 1
        $n_1_9 = "69802c98-2ce2-4a17-98z0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

