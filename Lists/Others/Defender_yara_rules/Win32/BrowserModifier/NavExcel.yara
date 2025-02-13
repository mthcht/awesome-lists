rule BrowserModifier_Win32_NavExcel_8860_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/NavExcel"
        threat_id = "8860"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "NavExcel"
        severity = "28"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.navexcel.com/" ascii //weight: 1
        $x_1_2 = "Software\\NavExcel Ltd\\NavExcel Search Toolbar" ascii //weight: 1
        $x_1_3 = "A new version of the NavExcel Search Toolbar." ascii //weight: 1
        $x_1_4 = "The NavExcel Search Toolbar will be upgraded at the next login." ascii //weight: 1
        $x_1_5 = "NavExcel Search Toolbar Update" ascii //weight: 1
        $x_1_6 = "NavExcelToolbar" ascii //weight: 1
        $x_1_7 = "\"%s\\update_install.exe\" -i -nq" ascii //weight: 1
        $x_1_8 = "Would you like to update the NavExcel Search Toolbar?" ascii //weight: 1
        $x_1_9 = "An update for the NavExcel Search Toolbar is available." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule BrowserModifier_Win32_NavExcel_8860_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/NavExcel"
        threat_id = "8860"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "NavExcel"
        severity = "28"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\NavExcel Search Toolbar" ascii //weight: 1
        $x_1_2 = "Are you sure you wish to uninstall the NavExcel" ascii //weight: 1
        $x_1_3 = "c:\\cygwin\\home\\quoc\\navexcel\\install\\Release\\remover.pdb" ascii //weight: 1
        $x_1_4 = "NavExcel Search Toolbar (remove only)" ascii //weight: 1
        $x_1_5 = "NavExcel Search Toolbar Installation Completed." ascii //weight: 1
        $x_1_6 = "NavExcel Search Toolbar Uninstallation" ascii //weight: 1
        $x_1_7 = "NavExcelBar.dll" ascii //weight: 1
        $x_1_8 = "nxstinst.exe" ascii //weight: 1
        $x_1_9 = "regsvr32.exe /s NavExcelBar.dll" ascii //weight: 1
        $x_1_10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NavExcel Search Toolbar" ascii //weight: 1
        $x_1_11 = "SOFTWARE\\NavExcel Ltd" ascii //weight: 1
        $x_1_12 = "The current user does not have sufficient privilege to install the NavExcel Search Toolbar." ascii //weight: 1
        $x_1_13 = "The NavExcel Search Toolbar has been successfully uninstalled." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule BrowserModifier_Win32_NavExcel_8860_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/NavExcel"
        threat_id = "8860"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "NavExcel"
        severity = "28"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "newnet search" ascii //weight: 1
        $x_1_2 = "hotbar search" ascii //weight: 1
        $x_1_3 = "commonname.com/find.asp?cn=" ascii //weight: 1
        $x_1_4 = "apps.webservicehost.com/apps/epa/epa?cid=" ascii //weight: 1
        $x_1_5 = "web.yoursearchfinder.net" ascii //weight: 1
        $x_1_6 = "tracker.tradedoubler.com/click" ascii //weight: 1
        $x_1_7 = "find.greatsearch.info/apps/eps/" ascii //weight: 1
        $x_1_8 = "result.goodsearch.info/apps/eps/" ascii //weight: 1
        $x_1_9 = "search.fastresults.org/apps/eps/" ascii //weight: 1
        $x_1_10 = "find.searchfact.net/apps/eps/" ascii //weight: 1
        $x_1_11 = "data.cybersearching.net/apps/eps/" ascii //weight: 1
        $x_1_12 = "data.quicksearches.net/apps/eps/" ascii //weight: 1
        $x_1_13 = "web.resultsondemand.net/apps/eps/" ascii //weight: 1
        $x_1_14 = "www.mysearchnet.org/apps/eps/" ascii //weight: 1
        $x_1_15 = "info.searchesdirect.net/apps/eps/" ascii //weight: 1
        $x_1_16 = "data.quicksearches.net" ascii //weight: 1
        $x_1_17 = "eps.new.search.new.net" ascii //weight: 1
        $x_2_18 = "NHUpdater.exe" ascii //weight: 2
        $x_2_19 = "NHUninstaller.exe" ascii //weight: 2
        $x_2_20 = "NHelper.dll" ascii //weight: 2
        $x_2_21 = "NavHelper Uninstaller" ascii //weight: 2
        $x_2_22 = "SOFTWARE\\NavExcel" ascii //weight: 2
        $x_2_23 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 2
        $x_2_24 = "navexcel.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*) and 16 of ($x_1_*))) or
            ((7 of ($x_2_*) and 14 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_NavExcel_8860_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/NavExcel"
        threat_id = "8860"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "NavExcel"
        severity = "28"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://www.commonname.com/find.asp?cn=" ascii //weight: 3
        $x_4_2 = "NavHelper File Delete Error!" ascii //weight: 4
        $x_4_3 = "Please visit http://www.navexcel.com for support on this issue." ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

