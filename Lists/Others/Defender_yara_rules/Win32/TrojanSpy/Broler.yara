rule TrojanSpy_Win32_Broler_A_2147750705_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Broler.A!dha"
        threat_id = "2147750705"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Broler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "taskmar.exe" ascii //weight: 5
        $x_1_2 = "\\doc_dll\\Release\\DocDll.pdb" ascii //weight: 1
        $x_1_3 = "\\Projects\\Expand\\Release\\Expand.pdb" ascii //weight: 1
        $x_5_4 = "RSDS" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Broler_B_2147750706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Broler.B!dha"
        threat_id = "2147750706"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Broler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Projects\\avenger\\Release\\avenger.pdb" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "winlogin.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Broler_C_2147750707_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Broler.C!dha"
        threat_id = "2147750707"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Broler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\jack\\Desktop\\test\\ec_new\\down_new\\Release\\down_new.pdb" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Frank\\Desktop\\ABK\\Release\\ABK.pdb" ascii //weight: 1
        $x_1_3 = "C:\\Users\\XF\\Documents\\Visual Studio 2010\\Projects\\ABK\\Release\\ABK.pdb" ascii //weight: 1
        $x_1_4 = "C:\\Users\\jack\\Desktop\\RAT\\C+\\Lilith-master\\x64\\Release\\Lilith.pdb" ascii //weight: 1
        $x_1_5 = "C:\\Users\\Frank\\Documents\\Visual Studio 2010\\Projects\\Avenger2\\Release\\Avenger2.pdb" ascii //weight: 1
        $x_1_6 = "C:\\Users\\jack\\Desktop\\test\\bug_mango\\down_new\\Release\\down_new.pdb" ascii //weight: 1
        $x_1_7 = "C:\\Users\\Frank\\Documents\\Visual Studio 2010\\Projects\\Expand\\Release\\Expand.pdb" ascii //weight: 1
        $x_1_8 = "C:\\Users\\jack\\Desktop\\RAT\\C+\\Lilith-master\\Release\\winlive.pdb" ascii //weight: 1
        $x_1_9 = "C:\\Users\\Frank\\Documents\\Visual Studio 2010\\Projects\\avenger\\Release\\avenger.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Broler_G_2147750708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Broler.G!dha"
        threat_id = "2147750708"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Broler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://www.longfeiye.com" ascii //weight: 5
        $x_5_2 = "http://27.255.90.158/TerminFold/ldsjr.php" ascii //weight: 5
        $x_1_3 = "SOFTWARE\\TrendMicro\\AMSP" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\360Safe\\Liveup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Broler_H_2147750709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Broler.H!dha"
        threat_id = "2147750709"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Broler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PccNT.exe" ascii //weight: 1
        $x_1_2 = "http://www.suamok.com//shop//img//marks_escrow//index.php" ascii //weight: 1
        $x_1_3 = "C:\\Users\\XF\\Documents\\Visual Studio 2010\\Projects\\ABKDLL\\Release\\ABKDLL.pdb" ascii //weight: 1
        $x_1_4 = "taskmgt.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Broler_RC_2147752197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Broler.RC!dha"
        threat_id = "2147752197"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Broler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b fe c7 45 ?? ?? ?? ?? ?? 6a ?? 6a ?? 6a ?? e8 ?? ?? ?? ?? 8b 45 ?? 32 04 37 6a ?? 6a ?? 6a ?? 88 06 e8 ?? ?? ?? ?? 8b 45 ?? 6a ?? c1 e0 ?? 6a ?? 89 45 ?? 6a ?? e8 ?? ?? ?? ?? 8b 45 ?? 6a ?? c1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

