rule Trojan_Win32_FileFix_D_2147945794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.D!MTB"
        threat_id = "2147945794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = ".docx" wide //weight: 1
        $x_1_3 = {2d 00 63 00 20 00 70 00 69 00 6e 00 67 00 [0-80] 23 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_DC_2147945906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.DC!MTB"
        threat_id = "2147945906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "112"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "; # --- Security identity" wide //weight: 10
        $x_10_3 = "; # Verify you are human" wide //weight: 10
        $x_10_4 = "; # ----- Identity" wide //weight: 10
        $x_10_5 = "$fab;" wide //weight: 10
        $x_1_6 = "Invoke-Expression $" wide //weight: 1
        $x_1_7 = "= Invoke-WebRequest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FileFix_A_2147945919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.A!MTB"
        threat_id = "2147945919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[System.Windows.Forms.MessageBox]::Show($" wide //weight: 1
        $x_1_2 = "Start-Process" wide //weight: 1
        $x_1_3 = "http" wide //weight: 1
        $x_1_4 = "System.Windows.Forms.SendKeys]::SendWait" wide //weight: 1
        $x_1_5 = "for($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_B_2147945920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.B!MTB"
        threat_id = "2147945920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "while($" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = ".docx" wide //weight: 1
        $x_1_4 = "[System.Windows.MessageBox]::Show(($" wide //weight: 1
        $x_1_5 = "Get-Random" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_DI_2147946487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.DI!MTB"
        threat_id = "2147946487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = {2d 00 63 00 20 00 70 00 69 00 6e 00 67 00 [0-80] 23 00}  //weight: 10, accuracy: Low
        $x_1_3 = ".docx" wide //weight: 1
        $x_1_4 = ".pdf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FileFix_DJ_2147947112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.DJ!MTB"
        threat_id = "2147947112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".Headers.Add(" wide //weight: 10
        $x_10_2 = ".DownloadString(" wide //weight: 10
        $x_10_3 = "Net.WebClient" wide //weight: 10
        $x_10_4 = "| iex" wide //weight: 10
        $x_10_5 = "schtasks /delete" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_DT_2147947978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.DT!MTB"
        threat_id = "2147947978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "161"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Powershell" wide //weight: 100
        $x_50_2 = "C:\\company\\" wide //weight: 50
        $x_50_3 = "C:\\internal-secure\\" wide //weight: 50
        $x_10_4 = ".docx" wide //weight: 10
        $x_10_5 = ".pdf" wide //weight: 10
        $x_10_6 = ".txt" wide //weight: 10
        $x_10_7 = ".ppt" wide //weight: 10
        $x_1_8 = " # " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FileFix_HB_2147947995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HB!MTB"
        threat_id = "2147947995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "106"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {2e 00 65 00 78 00 65 00 23 15 15 03 27 29 20 23 00 20 00}  //weight: 100, accuracy: Low
        $x_100_2 = {2e 00 70 00 73 00 31 00 23 15 15 03 27 29 20 23 00 20 00}  //weight: 100, accuracy: Low
        $x_5_3 = "curl " wide //weight: 5
        $x_5_4 = "powershell" wide //weight: 5
        $x_1_5 = " http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FileFix_EA_2147949392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.EA!MTB"
        threat_id = "2147949392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "115"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Powershell" wide //weight: 100
        $x_10_2 = "='xyz';" wide //weight: 10
        $x_5_3 = " # " wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_GGY_2147950077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.GGY!MTB"
        threat_id = "2147950077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 2d 00 63 00 [0-32] 70 00 69 00 6e 00 67 00 [0-60] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-16] 20 00 23 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_GGZ_2147950078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.GGZ!MTB"
        threat_id = "2147950078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[char]($_-bxor$" wide //weight: 1
        $x_1_2 = "join($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_HHA_2147950079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHA!MTB"
        threat_id = "2147950079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iex(irm $" wide //weight: 1
        $x_1_2 = ";iex $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_HHB_2147950080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHB!MTB"
        threat_id = "2147950080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::WriteAllBytes;$" wide //weight: 1
        $x_1_2 = "::ReadAllBytes;$" wide //weight: 1
        $x_1_3 = "[System.Convert];$" wide //weight: 1
        $x_1_4 = ".GetBytes;$" wide //weight: 1
        $x_1_5 = ":FromBase64String;$" wide //weight: 1
        $x_1_6 = "GetString;$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_HHC_2147950081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHC!MTB"
        threat_id = "2147950081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 61 00 73 00 70 00 78 00 [0-60] 20 00 23 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Start-Process http" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_HHC_2147950081_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHC!MTB"
        threat_id = "2147950081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Substring($($_" wide //weight: 1
        $x_1_2 = "-join" wide //weight: 1
        $x_1_3 = "ForEach-Object" wide //weight: 1
        $x_1_4 = "[char]([int]" wide //weight: 1
        $x_1_5 = "get-content" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_HHC_2147950081_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHC!MTB"
        threat_id = "2147950081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".GetString($convert::FromBase64String" wide //weight: 1
        $x_1_2 = ";&(bitsadmin.exe /transfer " wide //weight: 1
        $x_1_3 = "join($env:TEMP" wide //weight: 1
        $x_1_4 = ".GetString($" wide //weight: 1
        $x_1_5 = ".GetBytes($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_HHG_2147950448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHG!MTB"
        threat_id = "2147950448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "-outfile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_HHG_2147950448_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHG!MTB"
        threat_id = "2147950448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[Environment]::GetFolderPath" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = "|Get-Random -Count" wide //weight: 1
        $x_1_4 = "{[char]$_" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_HHI_2147950721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHI!MTB"
        threat_id = "2147950721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netsh wlan" wide //weight: 1
        $x_1_2 = "curl" wide //weight: 1
        $x_1_3 = "telegram" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_HHI_2147950721_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHI!MTB"
        threat_id = "2147950721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Start-Bitstransfer" wide //weight: 1
        $x_1_2 = "  # " wide //weight: 1
        $x_1_3 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileFix_HHF_2147951234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHF!MTB"
        threat_id = "2147951234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[System.Net.Sockets.TcpListener]" wide //weight: 1
        $x_1_2 = ".Start(" wide //weight: 1
        $x_1_3 = ".AcceptTcpClient();" wide //weight: 1
        $x_1_4 = ".GetStream()" wide //weight: 1
        $x_1_5 = ".Read($" wide //weight: 1
        $x_1_6 = "New-Object Byte[]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

