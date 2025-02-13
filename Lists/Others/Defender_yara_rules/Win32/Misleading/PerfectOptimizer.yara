rule Misleading_Win32_PerfectOptimizer_143135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/PerfectOptimizer"
        threat_id = "143135"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectOptimizer"
        severity = "35"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Miracle Technologies" wide //weight: 1
        $x_1_2 = "http://67.18.111.82:8088" ascii //weight: 1
        $x_1_3 = "\\Weskysoft\\" ascii //weight: 1
        $x_1_4 = "License.DLL" ascii //weight: 1
        $x_1_5 = "IsValidSN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Win32_PerfectOptimizer_143135_1
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/PerfectOptimizer"
        threat_id = "143135"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectOptimizer"
        severity = "35"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Weskysoft\\" wide //weight: 1
        $x_1_2 = "FConfigEvidenceScanItems" ascii //weight: 1
        $x_1_3 = "FConfigRegScanItems" ascii //weight: 1
        $x_1_4 = "FConfigQuickScanItems" ascii //weight: 1
        $x_1_5 = "FConfigFullScanItems" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Win32_PerfectOptimizer_143135_2
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/PerfectOptimizer"
        threat_id = "143135"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectOptimizer"
        severity = "35"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Perfect Optimizer" wide //weight: 1
        $x_1_2 = "Decrypt the serial number" wide //weight: 1
        $x_1_3 = "Miracle Technologies" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Win32_PerfectOptimizer_143135_3
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/PerfectOptimizer"
        threat_id = "143135"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectOptimizer"
        severity = "35"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WeskySoft" wide //weight: 1
        $x_1_2 = "Download Manager" wide //weight: 1
        $x_1_3 = "TDOWNLOADMAIN" wide //weight: 1
        $x_1_4 = "Sure you want to cancel Downloading?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Win32_PerfectOptimizer_143135_4
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/PerfectOptimizer"
        threat_id = "143135"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectOptimizer"
        severity = "35"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Miracle Technologies" wide //weight: 20
        $x_5_2 = "HistoryCleaner.dll" ascii //weight: 5
        $x_1_3 = "?__CleanAutoComplete" ascii //weight: 1
        $x_1_4 = "?__CleanDocument" ascii //weight: 1
        $x_1_5 = "?__CleanFindComputerMRU" ascii //weight: 1
        $x_1_6 = "?__CleanIECookie" ascii //weight: 1
        $x_1_7 = "?__CleanIEFavorite" ascii //weight: 1
        $x_1_8 = "?__CleanIETemp" ascii //weight: 1
        $x_1_9 = "?__CleanIEURL" ascii //weight: 1
        $x_1_10 = "?__CleanIEWebsite" ascii //weight: 1
        $x_1_11 = "?__CleanLogonMRU" ascii //weight: 1
        $x_1_12 = "?__CleanNetworkDrives" ascii //weight: 1
        $x_1_13 = "?__CleanRAS" ascii //weight: 1
        $x_1_14 = "?__CleanRecycleBin" ascii //weight: 1
        $x_1_15 = "?__CleanRunMRU" ascii //weight: 1
        $x_1_16 = "?__CleanSavePassword" ascii //weight: 1
        $x_1_17 = "?__CleanSearchFiles" ascii //weight: 1
        $x_1_18 = "?__CleanTelnetMRU" ascii //weight: 1
        $x_1_19 = "?__CleanWinTemp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 10 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Misleading_Win32_PerfectOptimizer_143135_5
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/PerfectOptimizer"
        threat_id = "143135"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectOptimizer"
        severity = "35"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ICO_ACTIVEXBLOCK" wide //weight: 1
        $x_1_2 = "ICO_DISKDEFRAG" wide //weight: 1
        $x_1_3 = "ICO_DRIVERBAK" wide //weight: 1
        $x_1_4 = "ICO_DUPLIFILECLEAR" wide //weight: 1
        $x_1_5 = "ICO_EVIDENCECLEANER" wide //weight: 1
        $x_1_6 = "ICO_FAVORITESBAK" wide //weight: 1
        $x_1_7 = "ICO_FILEASSOCREPAIR" wide //weight: 1
        $x_1_8 = "ICO_FILESHRED" wide //weight: 1
        $x_1_9 = "ICO_IEREPAIR" wide //weight: 1
        $x_1_10 = "ICO_JUNKFILECLEAN" wide //weight: 1
        $x_1_11 = "ICO_REGCLEANER" wide //weight: 1
        $x_1_12 = "ICO_REGDEFRAG" wide //weight: 1
        $x_1_13 = "ICO_REGISTRYBAK" wide //weight: 1
        $x_1_14 = "ICO_SHORTCUTCLEAR" wide //weight: 1
        $x_1_15 = "ICO_SHORTCUTREPAIR" wide //weight: 1
        $x_1_16 = "ICO_SOFTWAREUPDATE" wide //weight: 1
        $x_1_17 = "ICO_SPEEDUPMEM" wide //weight: 1
        $x_1_18 = "ICO_SPEEDUPNET" wide //weight: 1
        $x_1_19 = "ICO_SPEEDUPRUN" wide //weight: 1
        $x_1_20 = "ICO_SPEEDUPSYS" wide //weight: 1
        $x_1_21 = "ICO_SPYWARECLEAR" wide //weight: 1
        $x_1_22 = "ICO_SYSMAINTENACNE" wide //weight: 1
        $x_1_23 = "ICO_SYSOPTIMIZER" wide //weight: 1
        $x_1_24 = "ICO_SYSREPAIR" wide //weight: 1
        $x_1_25 = "ICO_SYSRESTORE" wide //weight: 1
        $x_1_26 = "ICO_UNINSTALLMANAGER" wide //weight: 1
        $x_1_27 = "ICO_WINDREPAIR" wide //weight: 1
        $x_1_28 = "ICO_WINUPDATE" wide //weight: 1
        $x_1_29 = "ICO_WORMBLOCK" wide //weight: 1
        $x_1_30 = "JUNK_FILE_CLEAN" wide //weight: 1
        $x_1_31 = "MMI_BLOCKACTIVEX" wide //weight: 1
        $x_1_32 = "MMI_BLOCKPOPUPS" wide //weight: 1
        $x_1_33 = "MMI_BLOCKPROGRAM_DOWN" wide //weight: 1
        $x_1_34 = "MMI_BLOCKWORMS" wide //weight: 1
        $x_1_35 = "MMI_DRIVERBACKUP" wide //weight: 1
        $x_1_36 = "MMI_DRIVERUPDATE" wide //weight: 1
        $x_1_37 = "MMI_DUPLICATEFILECLEAN" wide //weight: 1
        $x_1_38 = "MMI_EVIDENCECLEAN" wide //weight: 1
        $x_1_39 = "MMI_FAVORITEBACKUP" wide //weight: 1
        $x_1_40 = "MMI_FILEANALYZER" wide //weight: 1
        $x_1_41 = "MMI_FILEASSOCIATIONREAPIR" wide //weight: 1
        $x_1_42 = "MMI_FILEBACKUP" wide //weight: 1
        $x_1_43 = "MMI_FILEDEFRAGGER" wide //weight: 1
        $x_1_44 = "MMI_FILEENCRYPT" wide //weight: 1
        $x_1_45 = "MMI_FILETRANSFERMANAGER" wide //weight: 1
        $x_1_46 = "MMI_HARDWAREINFO" wide //weight: 1
        $x_1_47 = "MMI_IEREPAIR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (40 of ($x*))
}

rule Misleading_Win32_PerfectOptimizer_143135_6
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/PerfectOptimizer"
        threat_id = "143135"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectOptimizer"
        severity = "35"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2e 70 6f 78 00}  //weight: 2, accuracy: High
        $x_2_2 = {70 6f 66 69 6c 65 00}  //weight: 2, accuracy: High
        $x_2_3 = {50 65 72 66 65 63 74 20 4f 70 74 69 6d 69 7a 65 72 20 4c 69 63 65 6e 73 65 00}  //weight: 2, accuracy: High
        $x_2_4 = {50 65 72 66 65 63 74 4f 70 74 69 6d 69 7a 65 72 2e 69 6e 69 00}  //weight: 2, accuracy: High
        $x_1_5 = "TSPYWARESCANFRM" ascii //weight: 1
        $x_1_6 = "TFORMWORMS" ascii //weight: 1
        $x_1_7 = "TFrmSpyWareScan" ascii //weight: 1
        $x_1_8 = "Register->Invalid SN Code:" ascii //weight: 1
        $x_1_9 = "btn_FullScan_Normal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

