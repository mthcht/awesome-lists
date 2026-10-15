rule Trojan_Win32_SuspLoad_BA_2147980380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BA!MTB"
        threat_id = "2147980380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Reflection.Assembly]::Load" wide //weight: 1
        $x_1_2 = "|%{[int]$_" wide //weight: 1
        $x_1_3 = ").Split('|')" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLoad_BD_2147980387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BD!MTB"
        threat_id = "2147980387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Split(" wide //weight: 1
        $x_1_2 = "System.Web.HttpUtility]::UrlEncode" wide //weight: 1
        $x_1_3 = "::ToBase64String($" wide //weight: 1
        $x_1_4 = "-bxor $" wide //weight: 1
        $x_1_5 = "System.Web" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLoad_BE_2147980388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BE!MTB"
        threat_id = "2147980388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "; powershell" wide //weight: 1
        $x_1_2 = ".replace(' ',$" wide //weight: 1
        $x_1_3 = "-replace" wide //weight: 1
        $x_1_4 = "]::FromBase64String( $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLoad_BF_2147980389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BF!MTB"
        threat_id = "2147980389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[sysTEm.io.FILE]::reADAlLByTEs" wide //weight: 1
        $x_1_2 = "] -BXOR $" wide //weight: 1
        $x_1_3 = "::iNterACt()" wide //weight: 1
        $x_1_4 = "[sysTEM.REfLEctIon.asSembly]::LoaD($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLoad_BG_2147980390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BG!MTB"
        threat_id = "2147980390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[System.IO.File]::WriteAllBytes($" wide //weight: 1
        $x_1_2 = "bor($" wide //weight: 1
        $x_1_3 = "-bxor (($" wide //weight: 1
        $x_1_4 = "]::Parse(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLoad_BJ_2147980391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BJ!MTB"
        threat_id = "2147980391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Convert]::(('gnirtS46esaBmorF'" wide //weight: 1
        $x_1_2 = " -join ''" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLoad_BK_2147980392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BK!MTB"
        threat_id = "2147980392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "New-Object IO.MemoryStream(,$" wide //weight: 1
        $x_1_2 = "; Invoke-Expression $" wide //weight: 1
        $x_1_3 = "System.Security.Cryptography.AesManaged; $" wide //weight: 1
        $x_1_4 = ".CryptoStream($" wide //weight: 1
        $x_1_5 = ".CryptoStreamMode]::Read); $" wide //weight: 1
        $x_1_6 = "[Convert]::FromBase64String(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

