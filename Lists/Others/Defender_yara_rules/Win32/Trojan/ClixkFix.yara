rule Trojan_Win32_ClixkFix_NF_2147977830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NF!MTB"
        threat_id = "2147977830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "iex $" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-32] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = "irm " wide //weight: 1
        $x_1_4 = "param($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NG_2147977831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NG!MTB"
        threat_id = "2147977831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-join[char[]](" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-32] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = "irm " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NG_2147977831_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NG!MTB"
        threat_id = "2147977831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Start-Process powershell -ArgumentList @('-ExecutionPolicy', 'Bypass', '-File'" wide //weight: 1
        $x_1_2 = {24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 [0-32] 2e 00 70 00 73 00 31 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NI_2147977832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NI!MTB"
        threat_id = "2147977832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "('powershell -ep bypass -f '+[char]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NN_2147977834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NN!MTB"
        threat_id = "2147977834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ";powershell -E $" wide //weight: 1
        $x_1_2 = ";AntiBOT Check" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NJ_2147978268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NJ!MTB"
        threat_id = "2147978268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&call %" wide //weight: 1
        $x_1_2 = "|%comspec%" wide //weight: 1
        $x_1_3 = "start /min" wide //weight: 1
        $x_1_4 = "set " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NJ_2147978268_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NJ!MTB"
        threat_id = "2147978268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Screenshot\\]::CaptureScreens" wide //weight: 1
        $x_1_2 = ".Save(\"./Display $($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NK_2147978269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NK!MTB"
        threat_id = "2147978269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "join'')|iex" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NL_2147978270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NL!MTB"
        threat_id = "2147978270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo curl" wide //weight: 1
        $x_1_2 = " |iex" wide //weight: 1
        $x_1_3 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NM_2147978271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NM!MTB"
        threat_id = "2147978271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Content|powershell" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NQ_2147978272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NQ!MTB"
        threat_id = "2147978272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-32] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "$ExecutionContext.InvokeCommand.InvokeScript" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NR_2147978273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NR!MTB"
        threat_id = "2147978273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-32] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "& ((gal|?{$" wide //weight: 1
        $x_1_3 = "-match (" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NS_2147978274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NS!MTB"
        threat_id = "2147978274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-Headers @{(" wide //weight: 1
        $x_1_2 = "-UserAgent " wide //weight: 1
        $x_1_3 = "|iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

