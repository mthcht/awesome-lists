rule VirTool_Win32_Golazagne_A_2147797322_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Golazagne.A!MTB"
        threat_id = "2147797322"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Golazagne"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "browsers.decodedLoginData" ascii //weight: 1
        $x_1_2 = "browsers.AsnSourceDataMasterPassword" ascii //weight: 1
        $x_1_3 = "browsers.ChromeExtractDataRun" ascii //weight: 1
        $x_1_4 = "sysadmin.FilezillaExtractDataRun" ascii //weight: 1
        $x_1_5 = "sysadmin.retrieveHostname" ascii //weight: 1
        $x_1_6 = "goLazagne/filesystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

