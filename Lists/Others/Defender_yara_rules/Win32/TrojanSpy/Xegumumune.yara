rule TrojanSpy_Win32_Xegumumune_SP_2147840559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Xegumumune.SP!MTB"
        threat_id = "2147840559"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Xegumumune"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "*#*172.16.89.22XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX*#*" ascii //weight: 3
        $x_3_2 = "*#*abu20205858@gmail.com900------------------------------------*#*" ascii //weight: 3
        $x_2_3 = "uninstallmsfilter.exe" ascii //weight: 2
        $x_2_4 = "unregmail.bat" ascii //weight: 2
        $x_2_5 = "imonlspins64.exe -p -c b" ascii //weight: 2
        $x_2_6 = "install_lsp.exe -p" ascii //weight: 2
        $x_2_7 = "msflttrans.exe INSTALLCAB" ascii //weight: 2
        $x_2_8 = "ProcGuard.exe NOTRUNEXE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

