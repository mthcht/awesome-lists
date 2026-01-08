rule Trojan_Win32_Runner_AR_2147743490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Runner.AR!MTB"
        threat_id = "2147743490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "start mshta vbscript:createobject(\"wscript.shell\").run(\"\"\"C:\\kl\\ccc.cmd\"\" h\",0)(window.close)&&exit" ascii //weight: 10
        $x_10_2 = {53 54 41 52 54 20 68 74 74 70 3a 2f 2f 77 77 77 2e [0-9] 2e 74 77 2f [0-6] 2f 3f}  //weight: 10, accuracy: Low
        $x_10_3 = "c:\\kl\\ccc.cmd" ascii //weight: 10
        $x_10_4 = "C:\\kl\\ddd.cmd" ascii //weight: 10
        $x_1_5 = "cmd.exe /c copy" ascii //weight: 1
        $x_1_6 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "RegRead" ascii //weight: 1
        $x_1_8 = "regwrite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Runner_RP_2147910770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Runner.RP!MTB"
        threat_id = "2147910770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Mirc\\*.*" wide //weight: 1
        $x_1_2 = "unknowndll.pdb" ascii //weight: 1
        $x_1_3 = "Name Setup: Installing" ascii //weight: 1
        $x_1_4 = "Name Setup: Completed" ascii //weight: 1
        $x_1_5 = "ExecShell:" wide //weight: 1
        $x_1_6 = "NullsoftInst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Runner_CCJT_2147929896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Runner.CCJT!MTB"
        threat_id = "2147929896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 04 b2 01 f8 0f be 08 8d 58 01 b8 ?? ?? ?? ?? 85 c9 74 ?? 89 34 24 8d b4 26 00 00 00 00 66 90 89 c6 83 c3 01 c1 e6 05 01 c6 8d 04 0e 0f be 4b ?? 85 c9 75}  //weight: 2, accuracy: Low
        $x_1_2 = {83 ec 14 85 c0 75 ?? c7 04 24 ?? ?? ?? ?? ff d3 52 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Runner_HAB_2147960716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Runner.HAB!MTB"
        threat_id = "2147960716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bat.bat" ascii //weight: 2
        $x_2_2 = "bin.sfx.exe" ascii //weight: 2
        $x_2_3 = "vbs.vbs" ascii //weight: 2
        $x_5_4 = "WshShell.Run \"cmd.exe /c bat.bat\", 0, false" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

