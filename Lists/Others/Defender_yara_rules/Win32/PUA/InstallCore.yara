rule PUA_Win32_InstallCore_K_258557_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/InstallCore.K!!InstallCore.K"
        threat_id = "258557"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "InstallCore"
        severity = "Critical"
        info = "InstallCore: an internal category used to refer to some threats"
        info = "K: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 40 0f a2 3d fb 06 00 00 74 11 3d a1 06 02 00 75 1a 81 fa fd fb 8b 17 74 28 eb 10 81 fa ff fb 8b 0f 74 1e 81 fa ff fb 8b 1f 74 16 c1 e9 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PUA_Win32_InstallCore_R_266542_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/InstallCore.R"
        threat_id = "266542"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "InstallCore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "irsoGetInstHostVersion" ascii //weight: 1
        $x_1_2 = "irsoGetMainPackage" ascii //weight: 1
        $x_1_3 = "irsoSetCustomProgress" ascii //weight: 1
        $x_1_4 = "isroSetInstallerName" ascii //weight: 1
        $x_1_5 = "irsoUninstallAddOpenBrowserCmd" ascii //weight: 1
        $x_1_6 = "irsoIsCompleted" ascii //weight: 1
        $x_1_7 = "irsoCreateInternetShortcut" ascii //weight: 1
        $x_1_8 = "irsoGetChromeEXE" ascii //weight: 1
        $x_1_9 = "irsoGetDownloadedSize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PUA_Win32_InstallCore_M_267253_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/InstallCore.M"
        threat_id = "267253"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "InstallCore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 59 5a 50 68 52 75 6e 00 54 52 51 e8 07 00 00 00 90 ff d0 83 c4 04 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

