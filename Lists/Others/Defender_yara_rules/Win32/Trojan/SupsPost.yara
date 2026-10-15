rule Trojan_Win32_SupsPost_ZA_2147979640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZA!MTB"
        threat_id = "2147979640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|%{[char]([byte]$_-bxor $" wide //weight: 1
        $x_1_2 = "(([char[]]@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SupsPost_ZC_2147979641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZC!MTB"
        threat_id = "2147979641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Reflection.Assembly]::Load(" wide //weight: 1
        $x_1_2 = "[Convert]::ToString($" wide //weight: 1
        $x_1_3 = "-bxor $" wide //weight: 1
        $x_1_4 = "[Reflection.BindingFlags]" wide //weight: 1
        $x_1_5 = ".Invoke($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SupsPost_ZB_2147979642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZB!MTB"
        threat_id = "2147979642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "io.memorystream;$" wide //weight: 1
        $x_1_2 = "[convert]::frombase64string($" wide //weight: 1
        $x_1_3 = "-bxor $" wide //weight: 1
        $x_1_4 = ".Invoke($null,@(,[byte[]](" wide //weight: 1
        $x_1_5 = ".GetMethod('Load" wide //weight: 1
        $x_1_6 = "System.Reflection.Assembly" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SupsPost_ZD_2147979643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZD!MTB"
        threat_id = "2147979643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[byte][char]$" wide //weight: 1
        $x_1_2 = ";iEx $" wide //weight: 1
        $x_1_3 = "[Convert]::FromBase64String(" ascii //weight: 1
        $x_1_4 = "-bxor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SupsPost_ZE_2147979646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZE!MTB"
        threat_id = "2147979646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Convert]::FromBase64String([regex]::Replace($" wide //weight: 1
        $x_1_2 = "[char]($" wide //weight: 1
        $x_1_3 = "bxor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SupsPost_ZE_2147979646_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZE!MTB"
        threat_id = "2147979646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".AddressList" wide //weight: 10
        $x_10_2 = "net.webclient" wide //weight: 10
        $x_1_3 = "|iex" wide //weight: 1
        $x_1_4 = "|invoke-expression" wide //weight: 1
        $x_1_5 = ";iex" wide //weight: 1
        $x_1_6 = ";invoke-expression" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SupsPost_ZF_2147979647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZF!MTB"
        threat_id = "2147979647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[array]::Reverse($" wide //weight: 10
        $x_10_2 = ".ToCharArray();" wide //weight: 10
        $x_1_3 = "|iex" wide //weight: 1
        $x_1_4 = "|invoke-expression" wide //weight: 1
        $x_1_5 = ";iex" wide //weight: 1
        $x_1_6 = ";invoke-expression" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SupsPost_ZH_2147980372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZH!MTB"
        threat_id = "2147980372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.WebClient" wide //weight: 1
        $x_1_2 = "DownloadString($" wide //weight: 1
        $x_1_3 = "[System.Convert].GetMethod($" wide //weight: 1
        $x_1_4 = ".Invoke($" wide //weight: 1
        $x_1_5 = "IO.MemoryStream(,$" wide //weight: 1
        $x_1_6 = "System.Drawing.Bitmap]::FromStream($" wide //weight: 1
        $x_1_7 = "-bor([" wide //weight: 1
        $x_1_8 = "AppDomain]::CurrentDomain.GetAssemblies" wide //weight: 1
        $x_1_9 = "System.Reflection.Assembly" wide //weight: 1
        $x_1_10 = ".CopyTo($" wide //weight: 1
        $x_1_11 = ".GetString($" wide //weight: 1
        $x_1_12 = "Invoke-Expression $" wide //weight: 1
        $x_1_13 = "IO.Compression.CompressionMode" wide //weight: 1
        $x_1_14 = "http" wide //weight: 1
        $n_10_15 = "\\Program Files" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

