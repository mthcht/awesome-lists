rule Trojan_Win32_Repmord_A_2147690843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Repmord.A"
        threat_id = "2147690843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Repmord"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VideoDrivers\\GPU\\cgminer.exe" ascii //weight: 1
        $x_1_2 = "GPU\\cgminer.exe\" & Chr(34) & \" --scrypt -o stratum+tcp:" ascii //weight: 1
        $x_1_3 = "GPU\\run.vbs\" /RL HIGHEST" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

