rule Trojan_Win32_FakeMSA_A_2147598341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeMSA.A"
        threat_id = "2147598341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeMSA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Microsoft Security Adviser\\" wide //weight: 4
        $x_1_2 = "CurrentVersion\\Internet Settings\\Zones\\3" wide //weight: 1
        $x_1_3 = "\\Explorer\\Navigating\\.default" wide //weight: 1
        $x_1_4 = "CurrentVersion\\Policies\\System" wide //weight: 1
        $x_1_5 = "DisableTaskMgr" wide //weight: 1
        $x_2_6 = {31 00 30 00 30 00 31 00 00 00 00 00 08 00 00 00 31 00 30 00 30 00 34 00 00 00 00 00 08 00 00 00 31}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

