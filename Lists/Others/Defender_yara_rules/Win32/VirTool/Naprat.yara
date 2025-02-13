rule VirTool_Win32_Naprat_A_2147626355_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Naprat.A"
        threat_id = "2147626355"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Naprat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Documents and Settings\\zer0\\Desktop\\Projects\\PaiN RAT\\Client" ascii //weight: 1
        $x_1_2 = "Server.exe -srt -red -force -pdt" ascii //weight: 1
        $x_1_3 = "Use '%defaultbrowser%' To Inject into Default Browser" ascii //weight: 1
        $x_1_4 = "KeylogFile" ascii //weight: 1
        $x_1_5 = "PingInterval" ascii //weight: 1
        $x_1_6 = "btnDownloadToMemory" ascii //weight: 1
        $x_1_7 = "cbAntiAnubisSandbox" ascii //weight: 1
        $x_1_8 = "cbAntiNormanSandbox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

