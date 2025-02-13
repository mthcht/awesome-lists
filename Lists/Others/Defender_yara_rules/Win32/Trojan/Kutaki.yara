rule Trojan_Win32_Kutaki_MA_2147828812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kutaki.MA!MTB"
        threat_id = "2147828812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutaki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {9b 0b 88 26 08 99 7a 52 37 5c 47 c1 33 4c 5a 7e cf 01 91 04 b8 65 85 38 b9 41 d2 8a 46 8c 86 f8 2b 1c a9 bc a0 5c c8 35 9d bc 6a de 77 43 09 b4}  //weight: 10, accuracy: High
        $x_1_2 = "SHADO" wide //weight: 1
        $x_1_3 = "mufuckr" ascii //weight: 1
        $x_1_4 = "[ ALTDOWN ]" wide //weight: 1
        $x_1_5 = "taskkill /im" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kutaki_A_2147836647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kutaki.A!MTB"
        threat_id = "2147836647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutaki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "S  u  r  e" wide //weight: 2
        $x_2_2 = "taskkill /im" wide //weight: 2
        $x_2_3 = "achibat321X" wide //weight: 2
        $x_1_4 = "SHDocVwCtl.WebBrowser" ascii //weight: 1
        $x_2_5 = "\\st.htm" wide //weight: 2
        $x_2_6 = "\\wife" wide //weight: 2
        $x_2_7 = "namebro" wide //weight: 2
        $x_2_8 = "altafbhai" ascii //weight: 2
        $x_2_9 = "]eteleD[" wide //weight: 2
        $x_2_10 = "herlicopter" ascii //weight: 2
        $x_2_11 = "killerman" ascii //weight: 2
        $x_1_12 = "GetAsyncKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kutaki_GPA_2147912834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kutaki.GPA!MTB"
        threat_id = "2147912834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutaki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "uNewBitmapImage.bmp" ascii //weight: 5
        $x_2_2 = "aHR0cDovL25ld2xpbmt3b3RvbG92ZS5jbHViL2xvdmUvdGhyZWUucGhw" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

