rule Trojan_Win32_TinyNuke_AD_2147832763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TinyNuke.AD!MTB"
        threat_id = "2147832763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyNuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MainStub.dll" ascii //weight: 5
        $x_1_2 = "QbjDPSXdZkPAvSmCNk" ascii //weight: 1
        $x_1_3 = "VSgPsRsjmMGuHbXvBH" ascii //weight: 1
        $x_1_4 = "acwtKqMnZSTzeGlNaV" ascii //weight: 1
        $x_1_5 = "CurrentStake" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TinyNuke_MA_2147842171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TinyNuke.MA!MTB"
        threat_id = "2147842171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyNuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {26 16 ae 92 62 77 c0 c1 62 77 c0 c1 62 77 c0 c1 b1 05 c3 c0 69 77 c0 c1 b1 05 c5 c0 c1 77 c0 c1}  //weight: 5, accuracy: High
        $x_5_2 = {30 02 c4 c0 73 77 c0 c1 30 02 c3 c0 77 77 c0 c1 a0 9b 0e c1 60 77 c0 c1 b1 05 c1 c0 6f 77 c0 c1}  //weight: 5, accuracy: High
        $x_2_3 = "\\Bitcoin\\wallet.dat" ascii //weight: 2
        $x_1_4 = "GetClipboardData" ascii //weight: 1
        $x_1_5 = "QueryPerformanceCounter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TinyNuke_RDA_2147898724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TinyNuke.RDA!MTB"
        threat_id = "2147898724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyNuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HIDDENVNC" ascii //weight: 1
        $x_1_2 = "\\rundll32.exe shell32.dll,#61" ascii //weight: 1
        $x_1_3 = "TaskbarGlomLevel" ascii //weight: 1
        $x_1_4 = "shell_TrayWnd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

