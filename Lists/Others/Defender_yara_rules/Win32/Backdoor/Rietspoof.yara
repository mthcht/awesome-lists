rule Backdoor_Win32_Rietspoof_YA_2147733582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rietspoof.YA!MTB"
        threat_id = "2147733582"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rietspoof"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s%s%s USER: admin" ascii //weight: 1
        $x_1_2 = "Wscript.Sleep 1000*" ascii //weight: 1
        $x_1_3 = "data.dat" ascii //weight: 1
        $x_1_4 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rietspoof_A_2147733849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rietspoof.A"
        threat_id = "2147733849"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rietspoof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F:\\Work\\d2Od7s43\\revShell\\fwshell-master\\Release\\fwshell.pdb" ascii //weight: 1
        $x_1_2 = "104.248.177.188" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rietspoof_B_2147733850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rietspoof.B"
        threat_id = "2147733850"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rietspoof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fc ff ff ff 2b c7 83 e0 07 8b 34 82 b8 fe ff ff ff 2b c7 83 e0 07 8b 0c 82 8b c7 f7 d0 83 e0 07 8d 1c 82 8b d6 c1 ca 0b 8b c6 c1 c0 07 33 d0}  //weight: 1, accuracy: High
        $x_2_2 = {4d 39 68 35 61 6e 38 66 38 7a 54 6a 6e 79 54 77 51 56 68 36 68 59 42 64 59 73 4d 71 48 69 41 7a 00}  //weight: 2, accuracy: High
        $x_1_3 = {73 79 73 74 65 6d 0a 00 [0-6] 25 73 25 73 25 73 20 55 53 45 52 3a 20 75 73 65 72 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Rietspoof_B_2147733850_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rietspoof.B"
        threat_id = "2147733850"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rietspoof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s%s%s USER: user" ascii //weight: 1
        $x_1_2 = "data.dat" ascii //weight: 1
        $x_1_3 = "2x%.2x%.2x%.2x%.2x%" ascii //weight: 1
        $x_1_4 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" ascii //weight: 1
        $x_1_5 = "cmd /c %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

