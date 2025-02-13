rule Trojan_Win32_R2d2_A_2147650307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/R2d2.A!rootkit"
        threat_id = "2147650307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "R2d2"
        severity = "Critical"
        info = "rootkit: rootkit component of that malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PendingFileRenameOperations" wide //weight: 10
        $x_10_2 = "\\Device\\KeyboardClassC" wide //weight: 10
        $x_5_3 = "AppInit_DLLs" wide //weight: 5
        $x_5_4 = "mfc42ul.dll" wide //weight: 5
        $x_1_5 = "skype.exe" wide //weight: 1
        $x_1_6 = "paltalk.exe" wide //weight: 1
        $x_1_7 = "x-lite.exe" wide //weight: 1
        $x_1_8 = "voipbuster.exe" wide //weight: 1
        $x_1_9 = "simppro.exe" wide //weight: 1
        $x_1_10 = "simplite-icq-aim.exe" wide //weight: 1
        $x_1_11 = "icqlite.exe" wide //weight: 1
        $x_1_12 = "skypepm.exe" wide //weight: 1
        $x_1_13 = "lowratevoip.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_R2d2_A_2147650307_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/R2d2.A!rootkit"
        threat_id = "2147650307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "R2d2"
        severity = "Critical"
        info = "rootkit: rootkit component of that malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Driver\\kbdclass" wide //weight: 1
        $x_1_2 = "ZwSetInformationFile" ascii //weight: 1
        $x_1_3 = "PoStartNextPowerIrp" ascii //weight: 1
        $x_5_4 = "PendingFileRenameOperations" wide //weight: 5
        $x_5_5 = "\\Device\\KeyboardClassC" wide //weight: 5
        $x_1_6 = {3d 34 00 00 c0}  //weight: 1, accuracy: High
        $x_1_7 = {b8 9a 00 00 c0}  //weight: 1, accuracy: High
        $x_1_8 = {bb 10 00 00 c0}  //weight: 1, accuracy: High
        $x_5_9 = {68 a8 c5 00 00 68 8e 20 03 00 68 ef 01 00 00 6a 00 6a 01 ff 15 ?? ?? ?? ?? cc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

