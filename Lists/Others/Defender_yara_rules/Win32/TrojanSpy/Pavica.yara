rule TrojanSpy_Win32_Pavica_C_2147730172_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pavica.C!bit"
        threat_id = "2147730172"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pavica"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 55 6a 03 56 8b 35 ?? ?? ?? ?? 6a 03 53 6a ?? 68 ?? ?? ?? ?? ff d6 50 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = "/utils/inet_id_notify.php" ascii //weight: 1
        $x_1_3 = "rundll32.exe shell32.dll,ShellExec_RunDLL" wide //weight: 1
        $x_1_4 = {68 75 10 ad 01 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 59 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Pavica_PAEC_2147912110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pavica.PAEC!MTB"
        threat_id = "2147912110"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pavica"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c ren \"%s*.*\" *.*.%lu.bak" ascii //weight: 1
        $x_1_2 = "ping 1.1.1.1 -n %u & rmdir \"%s\" /q /s" ascii //weight: 1
        $x_1_3 = "cmd.exe" ascii //weight: 1
        $x_1_4 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_5 = "\\\\.\\PIPE\\" wide //weight: 1
        $x_1_6 = "SOFTWARE\\\\Usoris\\\\Backup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

