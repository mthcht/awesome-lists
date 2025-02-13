rule Worm_Win32_Muhu_B_2147601501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Muhu.B"
        threat_id = "2147601501"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Muhu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reproduce:" ascii //weight: 1
        $x_1_2 = "FileCopydir,C:\\ntdetec1\\child,%element%:\\,1" ascii //weight: 1
        $x_1_3 = "Regwrite,REG_SZ,HKEY_LOCAL_MACHINE,SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run,winlogon,C:\\ntdetec1\\run.exe" ascii //weight: 1
        $x_1_4 = "Loop, Read,C:\\ntdetec1\\driveList.txt" ascii //weight: 1
        $x_2_5 = {74 73 6b 63 6c 6f 73 65 3a 0d 0a 49 66 57 69 6e 45 78 69 73 74 2c 57 69 6e 64 6f 77 73 20 54 61 73 6b 20 4d 61 6e 61 67 65 72 0d 0a 20 20 7b 0d 0a 20 20 20 77 69 6e 63 6c 6f 73 65}  //weight: 2, accuracy: High
        $x_2_6 = {57 69 6e 47 65 74 41 63 74 69 76 65 54 69 74 6c 65 2c 20 65 64 0d 0a 20 69 66 69 6e 73 74 72 69 6e 67 2c 65 64 2c 70 72 6f 63 65 73 73 20 65 78 70 6c 6f 72 65 72 0d 0a 20 20 7b 0d 0a 20 20 20 77 69 6e 63 6c 6f 73 65 20 25 65 64 25}  //weight: 2, accuracy: High
        $x_1_7 = "settimer,ntdetec1" ascii //weight: 1
        $x_2_8 = "ifinstring,Title,Google search - Microsoft Internet Explorer" ascii //weight: 2
        $x_2_9 = "run,http://www.google.com/custom?hl=en&client=pub-2141221394801249&channel=7215448870" ascii //weight: 2
        $x_1_10 = "settimer,title,1000" ascii //weight: 1
        $x_2_11 = "FileCopy,%element%:\\ntdetec1.exe,c:\\ntdetec1\\child\\ntdetec1.exe,1" ascii //weight: 2
        $x_2_12 = "Filesetattrib,+SH,C:\\ntdetec1,1,1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

