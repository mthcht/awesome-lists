rule Trojan_Win32_Octopus_A_2147729959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Octopus.A!MTB"
        threat_id = "2147729959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Octopus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ping 1.1.1.1 -n 1 -w 800 > nul" wide //weight: 1
        $x_1_2 = "DownLoad File:" wide //weight: 1
        $x_1_3 = "Extract Files in:" wide //weight: 1
        $x_1_4 = "Move File: Out -" wide //weight: 1
        $x_1_5 = "Run Move File" wide //weight: 1
        $x_1_6 = "AutoRun List:" wide //weight: 1
        $x_1_7 = "s.bat" wide //weight: 1
        $x_1_8 = "/d.php" wide //weight: 1
        $x_1_9 = "UNKNOWNDLL.DLL" ascii //weight: 1
        $x_1_10 = "unknowndll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

