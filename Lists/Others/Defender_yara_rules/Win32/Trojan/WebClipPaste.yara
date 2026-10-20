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
        strings_accuracy = "Low"
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
        $x_20_43 = "[scriptblock]::Create" wide //weight: 20
        $x_20_44 = "[PowerShell]::Create()" wide //weight: 20
        $x_20_45 = {66 00 6f 00 72 00 [0-255] 63 00 6f 00 70 00 79 00 [0-48] 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00}  //weight: 20, accuracy: Low
        $x_20_46 = {73 00 74 00 61 00 72 00 74 00 02 00 20 00 2f 00 6d 00 69 00 6e 00 02 00 30 00 2f 00 76 00 3a 00 6f 00 6e 00 02 00 ff 00 25 00 74 00 65 00 6d 00 70 00 25 00}  //weight: 20, accuracy: Low
        $x_120_47 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 120, accuracy: Low
        $n_1000_48 = "/install" wide //weight: -1000
        $n_1000_49 = ".ps1" wide //weight: -1000
        $n_1000_50 = "(get-wmiobject -class win32_operatingsystem).caption" wide //weight: -1000
        $n_1000_51 = "windows defender advanced threat protection" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((6 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*))) or
            ((1 of ($x_120_*))) or
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
        strings_accuracy = "Low"
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
        $x_110_29 = "bitsadmin /transfer" wide //weight: 110
        $x_10_30 = "start-bitstransfer" wide //weight: 10
        $x_110_31 = "-urlcache" wide //weight: 110
        $x_10_32 = "regsvr32" wide //weight: 10
        $x_110_33 = "regsvr32 /i:http" wide //weight: 110
        $x_110_34 = "regsvr32 /s /n /u /i:" wide //weight: 110
        $x_10_35 = "rundll32" wide //weight: 10
        $x_110_36 = "rundll32 javascript:" wide //weight: 110
        $x_10_37 = "scrobj" wide //weight: 10
        $x_110_38 = "mshta" wide //weight: 110
        $x_110_39 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 [0-255] 68 00 74 00 74 00 70 00}  //weight: 110, accuracy: Low
        $x_10_40 = "--headless" wide //weight: 10
        $x_10_41 = "/v:on" wide //weight: 10
        $x_10_42 = "for /f" wide //weight: 10
        $x_10_43 = "delims=" wide //weight: 10
        $x_10_44 = "invokescript" wide //weight: 10
        $x_10_45 = "invokecommand" wide //weight: 10
        $x_10_46 = "-w 1 " wide //weight: 10
        $x_10_47 = "-w h " wide //weight: 10
        $x_10_48 = "[scriptblock]::Create" wide //weight: 10
        $x_10_49 = "[PowerShell]::Create()" wide //weight: 10
        $x_110_50 = {66 00 6f 00 72 00 [0-255] 63 00 6f 00 70 00 79 00 [0-48] 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00}  //weight: 110, accuracy: Low
        $x_110_51 = {73 00 74 00 61 00 72 00 74 00 02 00 20 00 2f 00 6d 00 69 00 6e 00 02 00 30 00 2f 00 76 00 3a 00 6f 00 6e 00 02 00 ff 00 25 00 74 00 65 00 6d 00 70 00 25 00}  //weight: 110, accuracy: Low
        $n_1000_52 = "/install" wide //weight: -1000
        $n_1000_53 = "(get-wmiobject -class win32_operatingsystem).caption" wide //weight: -1000
        $n_1000_54 = "windows defender advanced threat protection" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((11 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            ((1 of ($x_110_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WebClipPaste_C_2147980105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebClipPaste.C"
        threat_id = "2147980105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebClipPaste"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 100, accuracy: High
        $x_100_2 = {70 00 77 00 73 00 68 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 100, accuracy: High
        $x_100_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

