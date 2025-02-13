rule Ransom_Win32_JRanbt_WT_2147760626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/JRanbt.WT!MTB"
        threat_id = "2147760626"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "JRanbt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\Windows\\JRansomBootScreen.exe" ascii //weight: 1
        $x_1_2 = "taskmgr.exe,cmd.exe,chrome.exe,firefox.exe,opera.exe,microsoftedge.exe,microsoftedgecp.exe,notepad++,notepad.exe,iexplore.exe" ascii //weight: 1
        $x_1_3 = "jaemin1508@naver.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

