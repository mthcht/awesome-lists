rule Trojan_Win32_PinkyAgent_A_2147843202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PinkyAgent.A!dha"
        threat_id = "2147843202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PinkyAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "cd C:\\programdata\\service\\core && cmd.exe /C \"\"C:\\programdata\\Windows Events.exe\" \"C:\\programdata\\service\\core\\agent.py\"\"" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

