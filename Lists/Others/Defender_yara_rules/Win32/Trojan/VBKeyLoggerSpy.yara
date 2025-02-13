rule Trojan_Win32_VBKeyLoggerSpy_A_2147754161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKeyLoggerSpy.A!MTB"
        threat_id = "2147754161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKeyLoggerSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHDocVwCtl.WebBrowser" ascii //weight: 1
        $x_1_2 = "[Tab]" wide //weight: 1
        $x_1_3 = "[ALTUP]" wide //weight: 1
        $x_1_4 = "[ALTDOWN]" wide //weight: 1
        $x_1_5 = "[Escape]" wide //weight: 1
        $x_1_6 = "]pUegaP[" wide //weight: 1
        $x_1_7 = "]nwoDegaP[" wide //weight: 1
        $x_1_8 = "]dnE[" wide //weight: 1
        $x_1_9 = "]emoH[" wide //weight: 1
        $x_1_10 = "]tresnI[" wide //weight: 1
        $x_1_11 = "]eteleD[" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKeyLoggerSpy_B_2147754162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKeyLoggerSpy.B!MTB"
        threat_id = "2147754162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKeyLoggerSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHDocVwCtl.WebBrowser" ascii //weight: 1
        $x_1_2 = "[Tab]" wide //weight: 1
        $x_1_3 = "[ALTUP]" wide //weight: 1
        $x_1_4 = "[ALTDOWN]" wide //weight: 1
        $x_1_5 = "[Escape]" wide //weight: 1
        $x_1_6 = "[PageUp]" wide //weight: 1
        $x_1_7 = "[PageDown]" wide //weight: 1
        $x_1_8 = "[End]" wide //weight: 1
        $x_1_9 = "[Home]" wide //weight: 1
        $x_1_10 = "[Insert]" wide //weight: 1
        $x_1_11 = "[Delete]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKeyLoggerSpy_RA_2147772780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKeyLoggerSpy.RA!MTB"
        threat_id = "2147772780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKeyLoggerSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_2 = "PADwqeuui" ascii //weight: 1
        $x_1_3 = "C:\\warka\\kul\\194-1105\\prjsurbhi.vbp" wide //weight: 1
        $x_1_4 = "cmd.exe /c timeout.exe /T 11 & Del " wide //weight: 1
        $x_1_5 = "Win32_NetworkAdapterConfiguration" wide //weight: 1
        $x_1_6 = "a9ew64jszjh70gt909c0ji9ln2bm1um27i00a3hepj144emtht" wide //weight: 1
        $x_1_7 = "S  u  r  e" wide //weight: 1
        $x_1_8 = "\\h2.htm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

