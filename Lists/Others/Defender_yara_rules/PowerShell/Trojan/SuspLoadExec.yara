rule Trojan_PowerShell_SuspLoadExec_Z_2147972904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.Z!MTB"
        threat_id = "2147972904"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[IO.Compression.CompressionMode]::Decompress);$" wide //weight: 1
        $x_1_2 = "[Convert]::FromBase64String($" wide //weight: 1
        $x_1_3 = "New-Object IO.MemoryStream(,$" wide //weight: 1
        $x_1_4 = "IO.Compression.GZipStream($" wide //weight: 1
        $x_1_5 = "[Reflection.Assembly]::Load($" wide //weight: 1
        $x_1_6 = ".ToArray())|Out-Null;" wide //weight: 1
        $x_1_7 = ".CopyTo($" wide //weight: 1
        $x_1_8 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_SuspLoadExec_ZA_2147972905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZA!MTB"
        threat_id = "2147972905"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[guid]::NewGuid().ToString() + '.msi" wide //weight: 1
        $x_1_2 = ".DownloadFile($" wide //weight: 1
        $x_1_3 = ".WebClient" wide //weight: 1
        $x_1_4 = "System.Windows.Forms.MessageBox]::Show(" wide //weight: 1
        $x_1_5 = "$tmp$" wide //weight: 1
        $x_1_6 = "/qn" wide //weight: 1
        $x_1_7 = "/norestart" wide //weight: 1
        $x_1_8 = "[IO.Path]::Combine(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_SuspLoadExec_ZB_2147972906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZB!MTB"
        threat_id = "2147972906"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "join($a|%{-join($_.ToCharArray()|%" wide //weight: 1
        $x_1_2 = "IndexOf($_)+" wide //weight: 1
        $x_1_3 = "}:Unicode.GetString([Convert]::FromBase64String($" wide //weight: 1
        $x_1_4 = "})|iex" wide //weight: 1
        $x_1_5 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_SuspLoadExec_ZE_2147972907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZE!MTB"
        threat_id = "2147972907"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if (Get-Process" wide //weight: 1
        $x_1_2 = "| Where-Object { $_.ProcessName -like" wide //weight: 1
        $x_1_3 = "irm \"http" wide //weight: 1
        $x_1_4 = "Get-Variable MaximumVariableCount).Attributes" wide //weight: 1
        $x_1_5 = "$_ -is [System.Management.Automation.ValidateRangeAttribute]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_SuspLoadExec_ZG_2147972909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZG!MTB"
        threat_id = "2147972909"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String(" wide //weight: 1
        $x_1_2 = "System.Security.Cryptography" wide //weight: 1
        $x_1_3 = "WriteAllBytes(" wide //weight: 1
        $x_1_4 = "Shell.Application" wide //weight: 1
        $x_1_5 = "http" wide //weight: 1
        $x_1_6 = "GetTempPath(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_SuspLoadExec_ZH_2147972910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZH!MTB"
        threat_id = "2147972910"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String(" wide //weight: 1
        $x_1_2 = "System.Security.Cryptography" wide //weight: 1
        $x_1_3 = "WriteAllBytes(" wide //weight: 1
        $x_1_4 = "Shell.Application" wide //weight: 1
        $x_1_5 = "http" wide //weight: 1
        $x_1_6 = "GetTempPath(" wide //weight: 1
        $x_1_7 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_SuspLoadExec_ZI_2147972911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZI!MTB"
        threat_id = "2147972911"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 00 66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 [0-60] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = "} while ($" wide //weight: 1
        $x_1_4 = "]:::$???" wide //weight: 1
        $x_1_5 = "; do {$" wide //weight: 1
        $x_1_6 = ";while (!$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

