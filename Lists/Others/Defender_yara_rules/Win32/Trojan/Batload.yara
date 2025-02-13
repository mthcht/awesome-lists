rule Trojan_Win32_Batload_K_2147834534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Batload.K!MSR"
        threat_id = "2147834534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Batload"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "externalchecksso.com/g5i0nq" ascii //weight: 1
        $x_1_2 = "newtest.bat" ascii //weight: 1
        $x_1_3 = "avolkov\\x64\\Release Garb\\avolkov.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

