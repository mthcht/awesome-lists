rule TrojanSpy_Win32_Consyp_A_2147658408_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Consyp.A"
        threat_id = "2147658408"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Consyp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|ccSvcHst.exe|" ascii //weight: 1
        $x_1_2 = "|WindowsUpdate|systeminfo;netstat -na;net use;net user;dir \"%USERPROFILE%\\Recent\";" ascii //weight: 1
        $x_1_3 = "/index.php;http://" ascii //weight: 1
        $x_1_4 = "\\Startup\\wuauclt.exe\" /y & reg add" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

