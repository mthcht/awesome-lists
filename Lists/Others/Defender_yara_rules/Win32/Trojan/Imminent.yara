rule Trojan_Win32_Imminent_A_2147743688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Imminent.A!!Imminent.gen!A"
        threat_id = "2147743688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Imminent"
        severity = "Critical"
        info = "Imminent: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Imminent\\Path.dat" ascii //weight: 1
        $x_1_2 = "\\Imminent\\Logs\\" ascii //weight: 1
        $x_1_3 = "\\Imminent\\Plugins\\" ascii //weight: 1
        $x_1_4 = "KeyManager Ready" ascii //weight: 1
        $x_1_5 = "Microphone Ready." ascii //weight: 1
        $x_1_6 = "Miner killed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

