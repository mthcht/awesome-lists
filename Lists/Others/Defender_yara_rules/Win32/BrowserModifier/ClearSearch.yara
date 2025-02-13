rule BrowserModifier_Win32_ClearSearch_3729_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "software\\grip\\" ascii //weight: 1
        $x_1_2 = "00000000-0000-" ascii //weight: 1
        $x_1_3 = "Spider Found" ascii //weight: 1
        $x_1_4 = "Clear Search " wide //weight: 1
        $x_1_5 = "Explorer_Server" wide //weight: 1
        $x_1_6 = "&addr=%s&st=%d&eg=%d" wide //weight: 1
        $x_1_7 = "%s?guid=%s&" wide //weight: 1
        $x_1_8 = ".com/results.aspx?q=%s" wide //weight: 1
        $x_1_9 = "referer: %s" wide //weight: 1
        $x_1_10 = "\\InprocServer32" ascii //weight: 1
        $x_1_11 = "Apartment" ascii //weight: 1
        $x_1_12 = "ThreadingModel" ascii //weight: 1
        $x_1_13 = "Resolver Governor Hit" ascii //weight: 1
        $x_1_14 = "\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_15 = "RONSideBar" ascii //weight: 1
        $x_1_16 = "URLSideBar" ascii //weight: 1
        $x_1_17 = "Cycle %d Campaign" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

rule BrowserModifier_Win32_ClearSearch_3729_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ClrSrch_Connect" ascii //weight: 4
        $x_3_2 = "csAOLldr" ascii //weight: 3
        $x_1_3 = "InitInstance" ascii //weight: 1
        $x_1_4 = "TermInstance" ascii //weight: 1
        $x_4_5 = "ClrSrch_Disconnect" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_ClearSearch_3729_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/csie_usb_campaigns." ascii //weight: 3
        $x_3_2 = "Starting URLSideBar Process" ascii //weight: 3
        $x_3_3 = "USB Match" ascii //weight: 3
        $x_3_4 = "c:\\csie_debug.txt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_ClearSearch_3729_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Wait_For_Online" ascii //weight: 2
        $x_2_2 = "SOFTWARE\\ClrSch" ascii //weight: 2
        $x_2_3 = "promo=%d" ascii //weight: 2
        $x_2_4 = "BI installer" ascii //weight: 2
        $x_2_5 = "http://sds.clrsch.com/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_ClearSearch_3729_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://status.qckads.com/" ascii //weight: 3
        $x_3_2 = "http://sds.qckads.com/sidesearch/" ascii //weight: 3
        $x_3_3 = "csie_srchrule.dat" ascii //weight: 3
        $x_3_4 = "SOFTWARE\\LYCOS\\Sidesearch" ascii //weight: 3
        $x_3_5 = "/promo=%d&guid=%s" ascii //weight: 3
        $x_3_6 = "c:\\csie_debug.txt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule BrowserModifier_Win32_ClearSearch_3729_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\ClrSch" ascii //weight: 2
        $x_3_2 = "ClrSchUninstall" ascii //weight: 3
        $x_2_3 = "Lycos\\IEagent" ascii //weight: 2
        $x_3_4 = "CSIE.DLL" ascii //weight: 3
        $x_3_5 = "IE_ClrSch.DLL" ascii //weight: 3
        $x_3_6 = "ClrSchLoader" ascii //weight: 3
        $x_3_7 = "clrsch.com/loader" ascii //weight: 3
        $n_5_8 = "Redirects to certain sites based on where you browse" ascii //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_ClearSearch_3729_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CLEARSEARCH.DLL" ascii //weight: 2
        $x_2_2 = "ClrSrch_Connect" ascii //weight: 2
        $x_2_3 = "ClrSrch_Disconnect" ascii //weight: 2
        $x_2_4 = "ClrSrch_IsConnected" ascii //weight: 2
        $x_2_5 = "clear search version" ascii //weight: 2
        $x_2_6 = "clearsearch version" ascii //weight: 2
        $x_2_7 = "%s?guid=%s&fc=%d&p=%d&v=%d" ascii //weight: 2
        $x_2_8 = "http://r%d.clrsch.com/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule BrowserModifier_Win32_ClearSearch_3729_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Resolver returned 404" ascii //weight: 1
        $x_1_2 = "Resolver returned no data" ascii //weight: 1
        $x_3_3 = "clrsch:url" ascii //weight: 3
        $x_2_4 = "%s?guid=%s&addr=%s&st=%d&eg=%d&p=%d&ver=%d" ascii //weight: 2
        $x_3_5 = "http://r%d.clrsch.com/ie/" ascii //weight: 3
        $x_3_6 = "c:\\csie_debug.txt" ascii //weight: 3
        $x_2_7 = "Governor Hit - Attempt Lost" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_ClearSearch_3729_8
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "goodAOL.DL" ascii //weight: 1
        $x_2_2 = "csAOLldr.ex" ascii //weight: 2
        $x_1_3 = "Time to wake up, current time is %d." ascii //weight: 1
        $x_1_4 = "Sleeping for %ld milli-seconds ..." ascii //weight: 1
        $x_2_5 = "A_ClearSearch.DLL" ascii //weight: 2
        $x_3_6 = "CTAOLLDR.EXE" ascii //weight: 3
        $x_1_7 = "CSBB" ascii //weight: 1
        $x_1_8 = "Cleanup_Old_AOL_Plugins" ascii //weight: 1
        $x_3_9 = "CSAOLLDR.EXE" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_ClearSearch_3729_9
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "{947E6D5A-4B9F-4CF4-91B3-562CA8D03313}" ascii //weight: 4
        $x_1_2 = "CSAP.DLL" ascii //weight: 1
        $x_1_3 = "CSBB.DLL" ascii //weight: 1
        $x_1_4 = "CSIE.DLL" ascii //weight: 1
        $x_3_5 = "IE_CLRSCH.DLL" ascii //weight: 3
        $x_2_6 = "Excluded promo code #3 - not installing IE." ascii //weight: 2
        $x_1_7 = "Could not delete current thwarter plug-in!  Aborting install." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_ClearSearch_3729_10
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClearSearch"
        threat_id = "3729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearSearch"
        severity = "80"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Lycos\\IEagent" ascii //weight: 3
        $x_4_2 = "http://status.clrsch.com/loader/" ascii //weight: 4
        $x_3_3 = "ClrSchLoader" ascii //weight: 3
        $x_2_4 = "CSIE.DLL" ascii //weight: 2
        $x_2_5 = "IE_ClrSch.DLL" ascii //weight: 2
        $x_1_6 = "{00000000-0000-0000-0000-000000000221}" ascii //weight: 1
        $x_2_7 = "{7E53C1B1-49F0-498B-B0F8-B4BBF924A4AC}" ascii //weight: 2
        $x_1_8 = "{00000000-0000-0000-0000-000000000240}" ascii //weight: 1
        $x_2_9 = "{947E6D5A-4B9F-4CF4-91B3-562CA8D03313}" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

