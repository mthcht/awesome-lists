rule Trojan_Win32_RundllLolBin_AA_2147787818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AA"
        threat_id = "2147787818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = "javascript" wide //weight: 1
        $x_1_3 = "RunHTMLApplication" wide //weight: 1
        $x_1_4 = "ExecuteExcel4Macro" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RundllLolBin_AB_2147787819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AB"
        threat_id = "2147787819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = "javascript" wide //weight: 1
        $x_1_3 = "RunHTMLApplication" wide //weight: 1
        $x_1_4 = ".run" wide //weight: 1
        $x_1_5 = "wscript.shell" wide //weight: 1
        $x_1_6 = "eval(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_RundllLolBin_AC_2147787820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AC"
        threat_id = "2147787820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = "javascript" wide //weight: 1
        $x_1_3 = "RunHTMLApplication" wide //weight: 1
        $x_1_4 = ".exec(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RundllLolBin_AD_2147787821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AD"
        threat_id = "2147787821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = "javascript" wide //weight: 1
        $x_1_3 = "RunHTMLApplication" wide //weight: 1
        $x_1_4 = "script:http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RundllLolBin_AE_2147788905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AE"
        threat_id = "2147788905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = "javascript" wide //weight: 1
        $x_1_3 = "RunHTMLApplication" wide //weight: 1
        $x_1_4 = ".run" wide //weight: 1
        $x_1_5 = "wscript.shell" wide //weight: 1
        $x_1_6 = "eval(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_RundllLolBin_AF_2147793100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AF"
        threat_id = "2147793100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "lsass" wide //weight: 1
        $x_1_3 = "rundll32" wide //weight: 1
        $x_1_4 = "MiniDump" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RundllLolBin_AG_2147795800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AG"
        threat_id = "2147795800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bitsadmin.exe" wide //weight: 1
        $x_1_2 = "transfer" wide //weight: 1
        $x_1_3 = "https" wide //weight: 1
        $x_1_4 = ".xls" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RundllLolBin_AH_2147795801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AH"
        threat_id = "2147795801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" wide //weight: 1
        $x_1_2 = "create" wide //weight: 1
        $x_1_3 = ".js" wide //weight: 1
        $x_1_4 = "anydesk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RundllLolBin_AI_2147795802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AI"
        threat_id = "2147795802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "-command" wide //weight: 1
        $x_1_3 = "iex" wide //weight: 1
        $x_1_4 = "utf8.getstring" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RundllLolBin_AJ_2147795803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AJ"
        threat_id = "2147795803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "-command" wide //weight: 1
        $x_1_3 = "invoke-expression" wide //weight: 1
        $x_1_4 = "iex" wide //weight: 1
        $x_1_5 = ".invoke" wide //weight: 1
        $n_1_6 = "sentinelCommand" wide //weight: -1
        $n_1_7 = "customscripthandler" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (4 of ($x*))
}

rule Trojan_Win32_RundllLolBin_AK_2147796581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AK"
        threat_id = "2147796581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "-command" wide //weight: 1
        $x_1_3 = "invoke-expression" wide //weight: 1
        $x_1_4 = "iex" wide //weight: 1
        $x_1_5 = ".invoke" wide //weight: 1
        $x_1_6 = "FromBase64String" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

