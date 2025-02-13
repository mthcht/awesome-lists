rule TrojanSpy_Win32_Lespy_2147583227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lespy"
        threat_id = "2147583227"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lespy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e3a729da-eabc-df50-1842-dfd682644311" ascii //weight: 1
        $x_1_2 = "mswapi.dll" ascii //weight: 1
        $x_1_3 = "iehttpsendrequestmutex_%u" ascii //weight: 1
        $x_1_4 = "mycloseeventglobaframerl1" ascii //weight: 1
        $x_1_5 = "id=%08lX%08lX&ip=%s&title=%s&url=%s&data=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Lespy_A_2147616742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lespy.gen!A"
        threat_id = "2147616742"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lespy"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "iehttpsendrequestmutex_%u" ascii //weight: 2
        $x_2_2 = "id=%08lX%08lX&ip=%s&title=%s&url=%s&data" ascii //weight: 2
        $x_2_3 = "{e3a729da-eabc-df50-1842-dfd682644311}" ascii //weight: 2
        $x_2_4 = "mycloseeventglobaframerl1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

