rule TrojanDropper_Win32_Ficerip_A_2147721011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ficerip.A!dha"
        threat_id = "2147721011"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ficerip"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WScript.exe //B //Nologo //E:JScript" wide //weight: 1
        $x_1_2 = "MSOfficeMutex" ascii //weight: 1
        $x_1_3 = "win32kfull.sys" ascii //weight: 1
        $x_1_4 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_5 = {45 78 65 63 00 50 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

