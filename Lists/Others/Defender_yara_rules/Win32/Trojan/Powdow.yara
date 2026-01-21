rule Trojan_Win32_Powdow_HA_2147945900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powdow.HA!MTB"
        threat_id = "2147945900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "132"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "% {[Char]$_})" wide //weight: 100
        $x_20_2 = "{$null = $_}" wide //weight: 20
        $x_10_3 = "[char]0x" wide //weight: 10
        $x_1_4 = "FromBase64String" wide //weight: 1
        $x_1_5 = "Get-Random" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powdow_HC_2147948696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powdow.HC!MTB"
        threat_id = "2147948696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exe -r .\\preflight.js .\\app.jsc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powdow_HD_2147951098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powdow.HD!MTB"
        threat_id = "2147951098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "252"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {27 00 2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 27 00 [0-16] 27 00 2c 00 27 00 27 00 29 00 29 00 29 00 29 00}  //weight: 50, accuracy: Low
        $x_200_2 = {63 00 67 00 62 00 6a 00 61 00 67 00 34 00 61 00 64 00 67 00 62 00 76 00 61 00 67 00 73 00 [0-16] 61 00 7a 00 71 00 61 00 74 00 61 00 65 00 75 00 61 00 65 00 61 00 62 00 77 00 61 00 68 00 00}  //weight: 200, accuracy: Low
        $x_1_3 = "frombase64string" wide //weight: 1
        $x_1_4 = "iex(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powdow_HF_2147951099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powdow.HF!MTB"
        threat_id = "2147951099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 28 00 28 00 67 00 65 00 74 00 2d 00 63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 2d 00 72 00 61 00 77 00 29 00 2e 00 73 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 ?? ?? ?? ?? ?? ?? 29 00 29 00 3b 00 20 00 73 00 74 00 61 00 72 00 74 00 2d 00 73 00 6c 00 65 00 65 00 70 00}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powdow_SX_2147958426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powdow.SX!MTB"
        threat_id = "2147958426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Start-Process -FilePath \"powershell.exe\" -ArgumentList \"-EncodedCommand\", \"VwByAGkAdABlAC0ASABvAG0...\" -Wait" ascii //weight: 20
        $x_20_2 = "AMQAvAHIAZQBmAHMALwBoAGUAYQBkAHMALwBtAGEAaQBuAC8AdABlAHMAdAAuAHAAcwAxACIAIAAtAE8AdQB0AEYAaQBsAGUAIAAkAGcAaQBmAHAAYQB0AGgA" ascii //weight: 20
        $x_10_3 = "Start-Process -FilePath \"powershell.exe\" -ArgumentList \"-Command\", \"Remove-Item -Path '$ScriptLocation\\test1.exe'\"" ascii //weight: 10
        $x_10_4 = "$malw='Start-Process -FilePath \"powershell.exe\"-ArgumentList \".\\test256.ps1\" -wait'" ascii //weight: 10
        $x_1_5 = "Remove-Item -Path '$ScriptLocation\\test1.exe'" ascii //weight: 1
        $x_1_6 = "$gifpath = $pwd.Path+'\\svchost.exe'" ascii //weight: 1
        $x_1_7 = "Write-Host \"send to 18o8eKr8Sn3EBpGjNmXV4XdpEM5Hc1Fzte\"" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powdow_HH_2147961461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powdow.HH!MTB"
        threat_id = "2147961461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 6b 00 62 00 23 08 08 03 30 2d 39 2e 00 65 00 78 00 65 00 20 00 2d 00 65 00 20 00 79 00 77 00 62 00 74 00 61 00 67 00 71 00 61 00 69 00 61 00 61 00 76 00 61 00 67 00 6d 00 61 00 69 00 61 00 62 00 77 00 61 00 67 00 38 00 61 00 64 00 77 00 62 00 6c 00 61 00 68 00 69 00 61 00 63 00 77 00 62 00 6f 00 61 00 67 00 75 00 61 00 62 00 61 00 62 00 73 00 61 00 63 00}  //weight: 5, accuracy: Low
        $x_5_2 = "\\vcredist.exe -e ywbtagqaiaavagmaiabwag8adwblahiacwboaguababsa" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

