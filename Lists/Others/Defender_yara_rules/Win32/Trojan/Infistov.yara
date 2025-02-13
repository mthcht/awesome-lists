rule Trojan_Win32_Infistov_2147799670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Infistov"
        threat_id = "2147799670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Infistov"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MicrosoftEdgeElevationService" ascii //weight: 2
        $x_2_2 = "ACTION=ADMIN TARGETDIR=" ascii //weight: 2
        $x_2_3 = "\\\\.\\pipe\\ExploitPipe" ascii //weight: 2
        $x_1_4 = "\\microsoft plz" ascii //weight: 1
        $x_1_5 = "\\notepad.exe" ascii //weight: 1
        $x_1_6 = "\\splwow64.exe" ascii //weight: 1
        $x_1_7 = "\\@AppHelpToast.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Infistov_QW_2147805524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Infistov.QW!MTB"
        threat_id = "2147805524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Infistov"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "InstallerFileTakeOver.pdb" ascii //weight: 3
        $x_3_2 = "NtCompareTokens" ascii //weight: 3
        $x_3_3 = "ConvertStringSecurityDescriptorToSecurityDescriptorW" ascii //weight: 3
        $x_3_4 = "IsProcessorFeaturePresent" ascii //weight: 3
        $x_3_5 = "@AppHelpToast.png" ascii //weight: 3
        $x_3_6 = "C:\\File\\To\\Take\\Over" ascii //weight: 3
        $x_3_7 = "pipe\\ExploitPipe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Infistov_QQ_2147805945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Infistov.QQ!MTB"
        threat_id = "2147805945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Infistov"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "temp_dir" ascii //weight: 3
        $x_3_2 = "search_path" ascii //weight: 3
        $x_3_3 = "InstallerFileTakeOver.pdb" ascii //weight: 3
        $x_3_4 = "ConvertStringSecurityDescriptorToSecurityDescriptorW" ascii //weight: 3
        $x_3_5 = "ProductDir" ascii //weight: 3
        $x_3_6 = "Lockit" ascii //weight: 3
        $x_3_7 = "ImpersonateLoggedOnUser" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

