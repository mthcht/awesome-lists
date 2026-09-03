rule Trojan_Win32_WebClipPaste_A_2147977447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebClipPaste.A"
        threat_id = "2147977447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebClipPaste"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "120"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_100_2 = "pwsh" wide //weight: 100
        $x_100_3 = "cmd" wide //weight: 100
        $x_20_4 = "iex(" wide //weight: 20
        $x_20_5 = "iex " wide //weight: 20
        $x_20_6 = "invoke-expression" wide //weight: 20
        $x_20_7 = "irm " wide //weight: 20
        $x_20_8 = "iwr " wide //weight: 20
        $x_20_9 = "invoke-webrequest" wide //weight: 20
        $x_20_10 = "invoke-restmethod" wide //weight: 20
        $x_20_11 = "downloadstring" wide //weight: 20
        $x_20_12 = "downloadfile" wide //weight: 20
        $x_20_13 = "downloaddata" wide //weight: 20
        $x_20_14 = "webclient" wide //weight: 20
        $x_20_15 = "frombase64string" wide //weight: 20
        $x_20_16 = "-encodedcommand" wide //weight: 20
        $x_20_17 = "-enc " wide //weight: 20
        $x_20_18 = "-nop" wide //weight: 20
        $x_20_19 = "-noprofile" wide //weight: 20
        $x_20_20 = "-w hidden" wide //weight: 20
        $x_20_21 = "-windowstyle h" wide //weight: 20
        $x_20_22 = "-ep bypass" wide //weight: 20
        $x_20_23 = "-executionpolicy bypass" wide //weight: 20
        $x_20_24 = "-usebasicparsing" wide //weight: 20
        $x_20_25 = "curl " wide //weight: 20
        $x_20_26 = "wget " wide //weight: 20
        $x_20_27 = "certutil" wide //weight: 20
        $x_20_28 = "bitsadmin" wide //weight: 20
        $x_20_29 = "start-bitstransfer" wide //weight: 20
        $x_20_30 = "-urlcache" wide //weight: 20
        $x_20_31 = "regsvr32" wide //weight: 20
        $x_20_32 = "rundll32" wide //weight: 20
        $x_20_33 = "scrobj" wide //weight: 20
        $x_20_34 = "mshta" wide //weight: 20
        $x_20_35 = "--headless" wide //weight: 20
        $x_20_36 = "/v:on" wide //weight: 20
        $x_20_37 = "for /f" wide //weight: 20
        $x_20_38 = "delims=" wide //weight: 20
        $x_20_39 = "invokescript" wide //weight: 20
        $x_20_40 = "invokecommand" wide //weight: 20
        $x_20_41 = "-w 1 " wide //weight: 20
        $x_20_42 = "-w h " wide //weight: 20
        $n_1000_43 = "/install" wide //weight: -1000
        $n_1000_44 = ".ps1" wide //weight: -1000
        $n_1000_45 = "(get-wmiobject -class win32_operatingsystem).caption" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((6 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WebClipPaste_B_2147977448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebClipPaste.B"
        threat_id = "2147977448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebClipPaste"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_100_2 = "pwsh" wide //weight: 100
        $x_100_3 = "cmd" wide //weight: 100
        $x_10_4 = "iex(" wide //weight: 10
        $x_10_5 = "iex " wide //weight: 10
        $x_10_6 = "invoke-expression" wide //weight: 10
        $x_10_7 = "irm " wide //weight: 10
        $x_10_8 = "iwr " wide //weight: 10
        $x_10_9 = "invoke-webrequest" wide //weight: 10
        $x_10_10 = "invoke-restmethod" wide //weight: 10
        $x_10_11 = "downloadstring" wide //weight: 10
        $x_10_12 = "downloadfile" wide //weight: 10
        $x_10_13 = "downloaddata" wide //weight: 10
        $x_10_14 = "webclient" wide //weight: 10
        $x_10_15 = "frombase64string" wide //weight: 10
        $x_10_16 = "-encodedcommand" wide //weight: 10
        $x_10_17 = "-enc " wide //weight: 10
        $x_10_18 = "-nop" wide //weight: 10
        $x_10_19 = "-noprofile" wide //weight: 10
        $x_10_20 = "-w hidden" wide //weight: 10
        $x_10_21 = "-windowstyle h" wide //weight: 10
        $x_10_22 = "-ep bypass" wide //weight: 10
        $x_10_23 = "-executionpolicy bypass" wide //weight: 10
        $x_10_24 = "-usebasicparsing" wide //weight: 10
        $x_10_25 = "curl " wide //weight: 10
        $x_10_26 = "wget " wide //weight: 10
        $x_10_27 = "certutil" wide //weight: 10
        $x_10_28 = "bitsadmin" wide //weight: 10
        $x_10_29 = "start-bitstransfer" wide //weight: 10
        $x_10_30 = "-urlcache" wide //weight: 10
        $x_10_31 = "regsvr32" wide //weight: 10
        $x_10_32 = "rundll32" wide //weight: 10
        $x_10_33 = "scrobj" wide //weight: 10
        $x_10_34 = "mshta" wide //weight: 10
        $x_10_35 = "--headless" wide //weight: 10
        $x_10_36 = "/v:on" wide //weight: 10
        $x_10_37 = "for /f" wide //weight: 10
        $x_10_38 = "delims=" wide //weight: 10
        $x_10_39 = "invokescript" wide //weight: 10
        $x_10_40 = "invokecommand" wide //weight: 10
        $x_10_41 = "-w 1 " wide //weight: 10
        $x_10_42 = "-w h " wide //weight: 10
        $n_1000_43 = "/install" wide //weight: -1000
        $n_1000_44 = ".ps1" wide //weight: -1000
        $n_1000_45 = "(get-wmiobject -class win32_operatingsystem).caption" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((11 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

