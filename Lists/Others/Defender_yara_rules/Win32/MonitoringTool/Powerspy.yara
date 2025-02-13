rule MonitoringTool_Win32_Powerspy_C_147242_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Powerspy.C"
        threat_id = "147242"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Powerspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 00 70 00 6e 00 73 00 76 00 72 00 6d 00 00 00 0c 00 00 00 76 00 73 00 73 00 76 00 63 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 00 6d 00 61 00 74 00 72 00 69 00 78 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 62 00 75 00 79 00 2e 00 68 00 74 00 6d 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 6d 00 73 00 6e 00 61 00 70 00 70 00 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00 00 00 00 00 16 00 00 00 5c 00 6d 00 73 00 6e 00 75 00 73 00 72 00 2e 00 69 00 6e 00 69 00 00 00 1e 00 00 00 5c 00 65 00 6d 00 78 00 66 00 69 00 6c 00 65 00 30 00 30 00 31 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Powerspy_C_147242_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Powerspy.C"
        threat_id = "147242"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Powerspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 00 70 00 6e 00 73 00 76 00 72 00 6d 00 00 00 0c 00 00 00 76 00 73 00 73 00 76 00 63 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {59 00 61 00 68 00 6f 00 6f 00 21 00 20 00 4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 20 00 43 00 68 00 61 00 74 00 20 00 43 00 6f 00 6e 00 76 00 65 00 72 00 73 00 61 00 69 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "F:\\Development\\MSN Spy Monitor Trial\\Projects\\CP Project\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Powerspy_D_147488_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Powerspy.D"
        threat_id = "147488"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Powerspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 00 70 00 6e 00 73 00 76 00 72 00 79 00 00 00 0c 00 00 00 76 00 73 00 73 00 76 00 63 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 00 6d 00 61 00 74 00 72 00 69 00 78 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 62 00 75 00 79 00 2e 00 68 00 74 00 6d 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 79 00 69 00 6d 00 61 00 70 00 70 00 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00 00 00 00 00 16 00 00 00 5c 00 79 00 69 00 6d 00 75 00 73 00 72 00 2e 00 69 00 6e 00 69 00 00 00 1e 00 00 00 5c 00 65 00 6d 00 78 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Powerspy_E_147492_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Powerspy.E"
        threat_id = "147492"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Powerspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0e 00 00 00 6e 00 76 00 68 00 6f 00 73 00 74 00 76 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 65 00 6d 00 78 00 66 00 69 00 6c 00 65 00 2e 00 65 00 6d 00 78 00 00 00 00 00 14 00 00 00 5c 00 70 00 73 00 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00 00 00 00 00 1a 00 00 00 5c 00 70 00 73 00 61 00 70 00 70 00 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00}  //weight: 1, accuracy: High
        $x_1_3 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 73 00 79 00 6d 00 73 00 65 00 72 00 76 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Powerspy_E_147492_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Powerspy.E"
        threat_id = "147492"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Powerspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Monitor is not started yet. Do you still want to enter Stealth Mode?" wide //weight: 1
        $x_1_2 = "Logging Report</span></TD></TR></TABLE>" wide //weight: 1
        $x_1_3 = {65 00 6d 00 78 00 66 00 69 00 6c 00 65 [0-7] 2e 00 64 00 61 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Powerspy_F_148228_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Powerspy.F"
        threat_id = "148228"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Powerspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\psappini.ini" wide //weight: 1
        $x_1_2 = "psappinidx.ini" wide //weight: 1
        $x_1_3 = "bdmreg.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule MonitoringTool_Win32_Powerspy_H_153027_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Powerspy.H"
        threat_id = "153027"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Powerspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Monitor is already started!" wide //weight: 1
        $x_2_2 = "Keystrokes Typed" wide //weight: 2
        $x_2_3 = "ICQ Chat Conversaion" wide //weight: 2
        $x_3_4 = "Under Stealth Mode, this program" wide //weight: 3
        $x_2_5 = "the 'Send logs to your FTP" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Powerspy_I_156063_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Powerspy.I"
        threat_id = "156063"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Powerspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{Scroll Lock}" wide //weight: 1
        $x_1_2 = "scrshot" wide //weight: 1
        $x_1_3 = "Insert Into WinCaps (Username, Content) Values('" wide //weight: 1
        $x_1_4 = "Insert Into Keystrokes (Username, Content, WinCap, AppPath) Values('" wide //weight: 1
        $x_1_5 = "skype.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

