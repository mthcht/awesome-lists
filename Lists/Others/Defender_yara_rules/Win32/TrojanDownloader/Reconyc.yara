rule TrojanDownloader_Win32_Reconyc_BT_2147830941_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Reconyc.BT!MTB"
        threat_id = "2147830941"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\system32\\svch0st.exe" ascii //weight: 1
        $x_1_2 = "FunShion.ini" ascii //weight: 1
        $x_1_3 = "174.128.236.169" ascii //weight: 1
        $x_1_4 = "#$.exe" ascii //weight: 1
        $x_1_5 = "texapp.exe" ascii //weight: 1
        $x_1_6 = "C:\\Documents and Settings\\log.txt" ascii //weight: 1
        $x_1_7 = "bind source file is not exited!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

