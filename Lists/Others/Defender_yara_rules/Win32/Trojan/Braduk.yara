rule Trojan_Win32_Braduk_A_2147723531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Braduk.A!bit"
        threat_id = "2147723531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Braduk"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.minerURL" ascii //weight: 1
        $x_1_2 = "main.watchMiner" ascii //weight: 1
        $x_1_3 = ".commandCheckExploited" ascii //weight: 1
        $x_1_4 = ".downloadAndRun" ascii //weight: 1
        $x_1_5 = ".watchRegistryStartup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

