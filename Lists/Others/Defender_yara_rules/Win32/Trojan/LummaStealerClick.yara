rule Trojan_Win32_LummaStealerClick_A_2147931073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.A!MTB"
        threat_id = "2147931073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-split ($" wide //weight: 1
        $x_1_3 = ".CreateDecryptor(" wide //weight: 1
        $x_1_4 = "-replace" wide //weight: 1
        $x_1_5 = ".Substring(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_B_2147931148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.B!MTB"
        threat_id = "2147931148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "$env:computername" wide //weight: 1
        $x_1_3 = "iex $" wide //weight: 1
        $x_1_4 = "useragent" wide //weight: 1
        $x_1_5 = ".php?compname" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_D_2147931675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.D!MTB"
        threat_id = "2147931675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[system.io.file]::create($" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "$env:computername" wide //weight: 10
        $x_1_4 = "invoke-webrequest $" wide //weight: 1
        $x_1_5 = "iwr $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealerClick_I_2147932422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.I"
        threat_id = "2147932422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 [0-60] 7c 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00}  //weight: 10, accuracy: Low
        $x_10_2 = "iex" wide //weight: 10
        $x_1_3 = "mshta" wide //weight: 1
        $x_1_4 = "m*ta.e" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealerClick_K_2147932423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.K"
        threat_id = "2147932423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "iwr http" wide //weight: 1
        $x_1_4 = ".ps1 | iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_H_2147932737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.H"
        threat_id = "2147932737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "net.webclient" wide //weight: 10
        $x_10_3 = "[system.reflection.assembly]::load($" wide //weight: 10
        $x_10_4 = ".invoke($" wide //weight: 10
        $x_10_5 = ".headers.add($" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_AB_2147932739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.AB!MTB"
        threat_id = "2147932739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.webclient" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = ".name" wide //weight: 1
        $x_1_4 = ".invokecommand|get-member|where{" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_AB_2147932739_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.AB!MTB"
        threat_id = "2147932739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "$env:" wide //weight: 10
        $x_1_3 = "iex $" wide //weight: 1
        $x_1_4 = "invoke-expression $" wide //weight: 1
        $x_10_5 = "useragent" wide //weight: 10
        $x_10_6 = ".php?" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealerClick_Q_2147932741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.Q!MTB"
        threat_id = "2147932741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = "-Join" wide //weight: 1
        $x_1_4 = "I`E`X" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_S_2147932744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.S!MTB"
        threat_id = "2147932744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "telegram" wide //weight: 10
        $x_1_4 = "invoke-restmethod -uri" wide //weight: 1
        $x_1_5 = "iwr -uri" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealerClick_R_2147933212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.R!MTB"
        threat_id = "2147933212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "where-object{$" wide //weight: 10
        $x_10_3 = "[scriptblock]::create" wide //weight: 10
        $x_10_4 = "]::cmdlet)net." wide //weight: 10
        $x_1_5 = "http" wide //weight: 1
        $x_1_6 = ".shop" wide //weight: 1
        $x_1_7 = ".xyz" wide //weight: 1
        $x_1_8 = ".biz" wide //weight: 1
        $x_1_9 = ".cyou" wide //weight: 1
        $x_1_10 = ".click" wide //weight: 1
        $x_1_11 = ".lat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealerClick_T_2147933214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.T!MTB"
        threat_id = "2147933214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "pastebin.com/raw" wide //weight: 10
        $x_10_4 = "net.webclient" wide //weight: 10
        $x_10_5 = "download" wide //weight: 10
        $x_1_6 = ".exe" wide //weight: 1
        $x_1_7 = ".dll" wide //weight: 1
        $x_1_8 = ".ps1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealerClick_C_2147933474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.C!MTB"
        threat_id = "2147933474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "[io.path]::gettemppath(" wide //weight: 10
        $x_10_3 = "start-process -filepath $" wide //weight: 10
        $x_10_4 = "http" wide //weight: 10
        $x_10_5 = "foreach ($" wide //weight: 10
        $x_1_6 = "invoke-webrequest -uri $" wide //weight: 1
        $x_1_7 = "iwr -uri $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealerClick_U_2147934654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.U!MTB"
        threat_id = "2147934654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "add-mppreference" wide //weight: 1
        $x_1_3 = "-exclusion" wide //weight: 1
        $x_1_4 = "$env:" wide //weight: 1
        $x_1_5 = "net.webclient" wide //weight: 1
        $x_1_6 = ".download" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_V_2147935083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.V!MTB"
        threat_id = "2147935083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.webclient" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = ".name" wide //weight: 1
        $x_1_4 = "psobject.methods" wide //weight: 1
        $x_1_5 = "value" wide //weight: 1
        $x_1_6 = ").Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_W_2147935084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.W!MTB"
        threat_id = "2147935084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http" wide //weight: 10
        $x_10_2 = "php?action" wide //weight: 10
        $x_1_3 = "iex" wide //weight: 1
        $x_1_4 = "invoke-expression" wide //weight: 1
        $x_1_5 = "iwr" wide //weight: 1
        $x_1_6 = "invoke-webrequest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealerClick_Y_2147935504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.Y!MTB"
        threat_id = "2147935504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.webclient" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = ".name" wide //weight: 1
        $x_1_4 = "Get-Member" wide //weight: 1
        $x_1_5 = "value" wide //weight: 1
        $x_1_6 = ").Invoke" wide //weight: 1
        $x_1_7 = "Where{(Variable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_X_2147935729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.X!MTB"
        threat_id = "2147935729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "net.webclient" wide //weight: 10
        $x_10_2 = "reflection.assembly]::load($" wide //weight: 10
        $x_10_3 = ".invoke($" wide //weight: 10
        $x_10_4 = ".Convert]::FromBase64String($" wide //weight: 10
        $x_10_5 = ".GetMethod(" wide //weight: 10
        $x_10_6 = "http" wide //weight: 10
        $x_10_7 = ".DownloadData($" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

