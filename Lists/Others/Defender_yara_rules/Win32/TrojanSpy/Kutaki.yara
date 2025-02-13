rule TrojanSpy_Win32_Kutaki_MK_2147761541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kutaki.MK!MTB"
        threat_id = "2147761541"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutaki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S  u  r  e" wide //weight: 1
        $x_1_2 = "saverbro" wide //weight: 1
        $x_1_3 = "Wan t To  Clear  Log ??" wide //weight: 1
        $x_1_4 = "achibat321X" wide //weight: 1
        $x_1_5 = "SHDocVwCtl.WebBrowser" ascii //weight: 1
        $x_1_6 = "killerman" ascii //weight: 1
        $x_1_7 = "mufuckr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Kutaki_M_2147812649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kutaki.M!MTB"
        threat_id = "2147812649"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutaki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DTPicker" ascii //weight: 3
        $x_3_2 = "SHDocVwCtl.WebBrowser" ascii //weight: 3
        $x_3_3 = "Sleep" ascii //weight: 3
        $x_3_4 = "eyeshere" ascii //weight: 3
        $x_3_5 = "Logger" ascii //weight: 3
        $x_3_6 = "shelled" ascii //weight: 3
        $x_3_7 = "mufuckr" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Kutaki_EC_2147842270_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kutaki.EC!MTB"
        threat_id = "2147842270"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutaki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a9ew64jszjh70gt909c0ji9ln2bm1um27i00a3hepj144emtht" wide //weight: 1
        $x_1_2 = "Win32_NetworkAdapterConfiguration" wide //weight: 1
        $x_1_3 = "IPAddress" wide //weight: 1
        $x_1_4 = "oy7oel014pgx3rnmgo1floytt4o8eghapzuon70fhru0lnlsvl" wide //weight: 1
        $x_1_5 = "WScript.Shell" wide //weight: 1
        $x_1_6 = "taskkill /im" wide //weight: 1
        $x_1_7 = "killerman" ascii //weight: 1
        $x_1_8 = "SHDocVwCtl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Kutaki_SK_2147850742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kutaki.SK!MTB"
        threat_id = "2147850742"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutaki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "saverbro" wide //weight: 1
        $x_1_2 = "achibat321X" wide //weight: 1
        $x_1_3 = "SHDocVwCtl.WebBrowser" ascii //weight: 1
        $x_1_4 = "killerman" ascii //weight: 1
        $x_1_5 = "mufuckr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

