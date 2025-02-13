rule Trojan_Win32_Samcrex_A_2147725887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Samcrex.A!dha"
        threat_id = "2147725887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Samcrex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "<STARTCRED>" wide //weight: 10
        $x_10_2 = "<STARTPASS>" wide //weight: 10
        $x_10_3 = "<ENDCRED>" wide //weight: 10
        $x_10_4 = "_wfrcmd.vbs" wide //weight: 10
        $x_10_5 = "%programdata%\\evtchk.txt" wide //weight: 10
        $x_10_6 = {6a 01 6a 00 6a 02 6a 00 6a 00 6a 01 68 2a 02 28 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Samcrex_A_2147725887_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Samcrex.A!dha"
        threat_id = "2147725887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Samcrex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_wfrcmd.vbs && cscript.exe %ProgramData%\\_wfrcmd.vbs && %ProgramData%\\%COMPUTERNAME%.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

