rule BrowserModifier_Win32_CNNIC_3678_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\CNNIC\\CdnClient\\RunAct" wide //weight: 3
        $x_3_2 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CdnProt" wide //weight: 3
        $x_2_3 = "\\Device\\CdnPr" wide //weight: 2
        $x_4_4 = "\\CNNIC\\CdnClient\\InstallInfo" wide //weight: 4
        $x_4_5 = "CNNIC cdnprot" wide //weight: 4
        $x_2_6 = "cdnprot.sys" wide //weight: 2
        $x_3_7 = "\\DosDevices\\CdnProt" wide //weight: 3
        $x_1_8 = "IE URL Service" wide //weight: 1
        $x_1_9 = "Smart Card Event" wide //weight: 1
        $x_2_10 = "CnsMinKP" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "spie_StartHook" ascii //weight: 2
        $x_2_2 = "cdnspie.dll" ascii //weight: 2
        $x_2_3 = "cdnunins.exe" ascii //weight: 2
        $x_2_4 = "CdnHide" ascii //weight: 2
        $x_2_5 = "\\cdnprev.dat" ascii //weight: 2
        $x_2_6 = "\\cdnprot.dat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule BrowserModifier_Win32_CNNIC_3678_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 75 73 74 72 2e 64 6c 6c 00 63 6c 69 65 6e 74 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {68 70 12 00 00 68 38 90 00 10 [0-16] ff 15 04 80 00 10 [0-8] ff 15 00 80 00 10 33 c0 85 [0-8] 0f 95 c0}  //weight: 2, accuracy: Low
        $x_2_3 = "ERROR: Could not open IDE21201.VXD file" ascii //weight: 2
        $x_1_4 = {4e 65 74 62 69 6f 73 00 4e 45 54 41 50 49 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_CNNIC_3678_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 6c 69 65 6e 74 2e 44 4c 4c 00 63 6c 69 65 6e 74 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {68 70 12 00 00 68 38 90 00 10 [0-16] ff 15 04 80 00 10 [0-8] ff 15 00 80 00 10 33 c0 85 [0-8] 0f 95 c0}  //weight: 2, accuracy: Low
        $x_2_3 = "ERROR: Could not open IDE21201.VXD file" ascii //weight: 2
        $x_1_4 = {4e 65 74 62 69 6f 73 00 4e 45 54 41 50 49 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_CNNIC_3678_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[KDenyCharacterString]" ascii //weight: 1
        $x_1_2 = "[RegProtectDeny]" ascii //weight: 1
        $x_1_3 = "[TrustProcessName]" ascii //weight: 1
        $x_2_4 = "cdnprot.dat" ascii //weight: 2
        $x_1_5 = "[DenyProcessName]" ascii //weight: 1
        $x_2_6 = "9A578C98-3C2F-4630-890B-FC04196EF420" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\CNNIC\\CdnClient\\Common" ascii //weight: 2
        $x_2_2 = "SOFTWARE\\CNNIC\\CdnClient\\InstallInfo" ascii //weight: 2
        $x_3_3 = "%s\\update\\%s" ascii //weight: 3
        $x_3_4 = "cdnvers.dat" ascii //weight: 3
        $x_2_5 = "RelayUpdate" ascii //weight: 2
        $x_2_6 = "SOFTWARE\\CNNIC\\CdnClient\\Update" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SOFTWARE\\CNNIC\\CdnClient\\RunAct" ascii //weight: 3
        $x_3_2 = "SOFTWARE\\CNNIC\\CdnClient\\Update" ascii //weight: 3
        $x_3_3 = "SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\CDNCLIENT\\" ascii //weight: 3
        $x_3_4 = "/cdnClient/update" ascii //weight: 3
        $x_2_5 = "cdnunins.exe" ascii //weight: 2
        $x_1_6 = "Update completed." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Uninstall c-Nav.lnk" ascii //weight: 2
        $x_2_2 = "About c-Nav.url" ascii //weight: 2
        $x_3_3 = "cdnaux.dll" ascii //weight: 3
        $x_1_4 = "ManagerShortCut" ascii //weight: 1
        $x_2_5 = ":\\Program Files\\CNNIC\\Cdn\\" ascii //weight: 2
        $x_2_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CdnClient" ascii //weight: 2
        $x_2_7 = "SOFTWARE\\CNNIC\\CdnClient\\Common" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_8
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdnup" ascii //weight: 1
        $x_2_2 = "Software\\CNNIC\\CdnClient\\Display\\TypedVKWs" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\CDNCLIENT" ascii //weight: 2
        $x_2_4 = "Chinese Navigation" ascii //weight: 2
        $x_2_5 = "cdnprh.dll" ascii //weight: 2
        $x_2_6 = "prh_SetFilter" ascii //weight: 2
        $x_2_7 = "Enable Chinese Domain Name Mailing System" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_9
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Chinese Navigation Upgrade" ascii //weight: 3
        $x_3_2 = "SOFTWARE\\CNNIC\\CdnClient\\Update" ascii //weight: 3
        $x_3_3 = "SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\CDNCLIENT\\UPDATE\\POPUP" ascii //weight: 3
        $x_3_4 = "CNNIC News Window" ascii //weight: 3
        $x_2_5 = "EnableTaskPopup" ascii //weight: 2
        $x_5_6 = "cdn_mutex_cdnupwin" ascii //weight: 5
        $x_3_7 = "cdnuplib.dll" ascii //weight: 3
        $x_2_8 = "RelayUpdate" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_10
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "cdnprh.dll" ascii //weight: 3
        $x_3_2 = "SYSTEM\\CurrentControlSet\\Services\\Cdnprot" ascii //weight: 3
        $x_4_3 = "\\\\.\\CDNPROT" ascii //weight: 4
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\Browser\\Security" ascii //weight: 1
        $x_3_5 = "System\\CurrentControlSet\\Services\\VxD\\Cdnprot" ascii //weight: 3
        $x_3_6 = "cdnprot.vxd" ascii //weight: 3
        $x_3_7 = "System\\CurrentControlSet\\Services\\CnsMinKP" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_11
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "idnconv.dll" ascii //weight: 1
        $x_1_2 = "idnconvs.dll" ascii //weight: 1
        $x_2_3 = "CnsMin" ascii //weight: 2
        $x_2_4 = "RedBurgee" ascii //weight: 2
        $x_2_5 = "SOFTWARE\\CNNIC\\CdnClient\\Console" ascii //weight: 2
        $x_2_6 = "SOFTWARE\\CNNIC\\CdnClient\\InstallInfo" ascii //weight: 2
        $x_1_7 = "idn_free" ascii //weight: 1
        $x_2_8 = "SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\CDNCLIENT\\IDNKW\\" ascii //weight: 2
        $x_2_9 = "EnableKw" ascii //weight: 2
        $x_2_10 = "EnableIdn" ascii //weight: 2
        $x_1_11 = "cdndet.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_12
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "CdnSign.dll" ascii //weight: 4
        $x_1_2 = "Csn_SplitSgnFile" ascii //weight: 1
        $x_1_3 = "Csn_VerifySgnFile" ascii //weight: 1
        $x_2_4 = "CA5F136A67C6B50ABB0BE8FAC9A2B4B3C4F15731A5E63E42CAD3193C7FAE0E167133D2B9E174E5A90D7DA2DC4FA5B2F68921AC5725261C2F45D9C25A63204FBC3631798984A3403D6B64A54A6617AD753EE573AFEEB108A72F340546F32BF41469FE9DD10C87DC5DD0F65FAD95182A01EAA8B563588ED78176362ED014CB18" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_13
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdnprh.dll" ascii //weight: 1
        $x_1_2 = "cdnprot.sys" ascii //weight: 1
        $x_1_3 = "cdnunins.exe" ascii //weight: 1
        $x_1_4 = "cdnup.exe" ascii //weight: 1
        $x_1_5 = "cdnvers.dat" ascii //weight: 1
        $x_1_6 = "idnconvs.dll" ascii //weight: 1
        $x_2_7 = "SYSTEM\\CurrentControlSet\\Services\\cdnprot" ascii //weight: 2
        $x_2_8 = "SOFTWARE\\CNNIC\\CdnClient\\Common" ascii //weight: 2
        $x_2_9 = "Install will continue after restarting computer!" ascii //weight: 2
        $x_2_10 = "Do you reboot now?" ascii //weight: 2
        $x_4_11 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\cdn" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_14
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "prh_UnInstallDriver" ascii //weight: 3
        $x_3_2 = "cdnprot.dat" ascii //weight: 3
        $x_3_3 = "cdnup.exe" ascii //weight: 3
        $x_3_4 = "cdnvers.dat" ascii //weight: 3
        $x_3_5 = "CdnCtr" ascii //weight: 3
        $x_3_6 = "SOFTWARE\\Microsoft\\Code Store Database\\Distribution Units\\{9A578C98-3C2F-4630-890B-FC04196EF420}" ascii //weight: 3
        $x_3_7 = "http://name.cnnic.cn/cn.dll" ascii //weight: 3
        $x_3_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CdnClient" ascii //weight: 3
        $x_3_9 = "SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\CDNCLIENT" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule BrowserModifier_Win32_CNNIC_3678_15
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Csn_SplitSgnFile" ascii //weight: 1
        $x_1_2 = "Csn_VerifySgnFile" ascii //weight: 1
        $x_1_3 = "cnprov.dat" ascii //weight: 1
        $x_1_4 = "adprot.sys" ascii //weight: 1
        $x_4_5 = "\\cdnprot\\driver\\objfre\\i386\\cnprov.pdb" ascii //weight: 4
        $x_4_6 = "http://name.cnnic.cn/cn.dll?pid=" ascii //weight: 4
        $x_1_7 = "cdnhint" ascii //weight: 1
        $x_1_8 = "cdnpopup" ascii //weight: 1
        $x_4_9 = "Chinese Domain Name client-end software has been detected, would you like to " ascii //weight: 4
        $x_4_10 = "<form name=\"f\" action=\"http://name.cnnic.cn/cn.dll\">" ascii //weight: 4
        $x_4_11 = "window.open(\"http://name.cnnic.cn/cn.dll?charset=utf-8&name=\"+qe);" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_16
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[RegProtectDeny]" ascii //weight: 1
        $x_1_2 = "[TrustProcessName]" ascii //weight: 1
        $x_1_3 = "cnprov.dat" ascii //weight: 1
        $x_1_4 = "CDNUNINS.EXE" ascii //weight: 1
        $x_1_5 = "CDNUP.EXE" ascii //weight: 1
        $x_4_6 = "\\cdnprot\\driver\\objfre\\i386\\cnprov.pdb" ascii //weight: 4
        $x_3_7 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\cnprov" wide //weight: 3
        $x_2_8 = "ADPROT.SYS" wide //weight: 2
        $x_3_9 = "\\BaseNamedObjects\\7EA4D072-3BF7-4acf-BD21-FAF21EF11090" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_17
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "IP-CNNIC" ascii //weight: 4
        $x_1_2 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces" wide //weight: 1
        $x_2_3 = "\\REGISTRY\\MACHINE\\SOFTWARE\\CNNIC\\CdnClient\\InstallInfo" wide //weight: 2
        $x_2_4 = "\\cdntran.dat" wide //weight: 2
        $x_3_5 = "\\Device\\CDNTRAN" wide //weight: 3
        $x_3_6 = "\\DosDevices\\CDNTRAN" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_18
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "install.exe" ascii //weight: 1
        $x_1_2 = "setup.exe" ascii //weight: 1
        $x_1_3 = "{7CA83CF1-3AEA-42D0-A4E3-1594FC6E48B2}" ascii //weight: 1
        $x_1_4 = "{1B0E7716-898E-48CC-9690-4E338E8DE1D3}" ascii //weight: 1
        $x_1_5 = "{ABEC6103-F6AC-43A3-834F-FB03FBA339A2}" ascii //weight: 1
        $x_1_6 = "{BB936323-19FA-4521-BA29-ECA6A121BC78}" ascii //weight: 1
        $x_1_7 = "{D157330A-9EF3-49F8-9A67-4141AC41ADD4}" ascii //weight: 1
        $x_1_8 = "{B83FC273-3522-4CC6-92EC-75CC86678DA4}" ascii //weight: 1
        $x_5_9 = "\\drivers\\wincl.sys" ascii //weight: 5
        $x_8_10 = "\\\\.\\CNSMINKP.VXD" ascii //weight: 8
        $x_5_11 = "\\\\.\\WINCL.VXD" ascii //weight: 5
        $x_5_12 = "\\wincl.vxd" ascii //weight: 5
        $x_4_13 = "Install will continue after restarting computer!" ascii //weight: 4
        $x_4_14 = "Do you reboot now?" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_8_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_8_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_3678_19
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC"
        threat_id = "3678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "84"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SOFTWARE\\CNNIC\\CdnClient\\Update" ascii //weight: 3
        $x_3_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{D157330A-9EF3-49F8-9A67-4141AC41ADD4}" ascii //weight: 3
        $x_3_3 = "SOFTWARE\\CNNIC\\CdnClient\\RunAct" ascii //weight: 3
        $x_3_4 = "SOFTWARE\\CNNIC\\CdnClient\\InstallInfo" ascii //weight: 3
        $x_3_5 = "SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\CDNCLIENT\\" ascii //weight: 3
        $x_3_6 = "Chinese Navigation" ascii //weight: 3
        $x_3_7 = "SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\{5C3853CF-C7E0-4946-B3FA-1ABDB6F48108}" ascii //weight: 3
        $x_2_8 = "Auto-Suggest Dropdown" wide //weight: 2
        $x_3_9 = "Software\\CNNIC\\CdnClient\\Display\\TypedSKWs" ascii //weight: 3
        $x_3_10 = "Software\\CNNIC\\CdnClient\\Display\\TypedVKWs" ascii //weight: 3
        $x_3_11 = "Software\\CNNIC\\CdnClient\\Display\\TypedSKWs" wide //weight: 3
        $x_3_12 = "Software\\CNNIC\\CdnClient\\Display\\TypedVKWs" wide //weight: 3
        $x_2_13 = "http://name.cnnic." ascii //weight: 2
        $x_2_14 = "http://name.cnnic." wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 3 of ($x_2_*))) or
            ((5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((6 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CNNIC_DLL_132376_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CNNIC.DLL"
        threat_id = "132376"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CNNIC"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 6f 66 74 77 61 72 65 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 43 6f 6e 73 6f 6c 65 00}  //weight: 10, accuracy: High
        $x_1_2 = {63 64 6e 6e 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 63 64 6e 63 6d 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 64 6e 63 6f 6e 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "cdntran" ascii //weight: 1
        $x_1_6 = "CDNCLIENT\\MAIL" ascii //weight: 1
        $x_1_7 = {63 64 6e 74 64 6e 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {69 6d 61 64 6f 6d 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {57 4d 48 6c 70 72 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_10 = {63 64 6e 75 6e 69 6e 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {69 6d 61 6f 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

