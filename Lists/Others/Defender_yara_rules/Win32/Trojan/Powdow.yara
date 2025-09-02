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

