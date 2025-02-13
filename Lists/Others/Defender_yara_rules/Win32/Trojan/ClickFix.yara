rule Trojan_Win32_ClickFix_A_2147924937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.A!MTB"
        threat_id = "2147924937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-command $" wide //weight: 1
        $x_1_3 = "Invoke-WebRequest -Uri $" wide //weight: 1
        $x_1_4 = ".Content; iex $" wide //weight: 1
        $x_1_5 = "\\1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_B_2147924938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.B!MTB"
        threat_id = "2147924938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta http" wide //weight: 1
        $x_1_2 = ".html #" wide //weight: 1
        $x_1_3 = "''\\1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_D_2147924939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.D!MTB"
        threat_id = "2147924939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_3 = "recaptcha" wide //weight: 1
        $x_1_4 = "verif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_F_2147924940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.F!MTB"
        threat_id = "2147924940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "| iex" wide //weight: 1
        $x_1_3 = "recaptcha" wide //weight: 1
        $x_1_4 = "verif" wide //weight: 1
        $x_1_5 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_F_2147924940_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.F!MTB"
        threat_id = "2147924940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta http" wide //weight: 1
        $x_1_2 = ".html #" wide //weight: 1
        $x_1_3 = "''\\1" wide //weight: 1
        $x_1_4 = "Verify" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DA_2147924941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DA!MTB"
        threat_id = "2147924941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "Hidden" wide //weight: 1
        $x_10_3 = "-eC" wide //weight: 10
        $x_10_4 = "aQBlAHgAIAAoAGkAdwByACAAaAB0AHQAcABzADoALwAvA" wide //weight: 10
        $x_10_5 = "aQBlAHgAIAAoAGkAdwByACAAaAB0AHQAcAA6AC8ALwAxA" wide //weight: 10
        $x_1_6 = "\\1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_G_2147931877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.G!MTB"
        threat_id = "2147931877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = ".mp4?" wide //weight: 1
        $x_1_4 = "verif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DB_2147932129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DB!MTB"
        threat_id = "2147932129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = ".html #" wide //weight: 1
        $x_1_4 = "verif" wide //weight: 1
        $x_1_5 = "- ray" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DC_2147932130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DC!MTB"
        threat_id = "2147932130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "\\*i*" wide //weight: 10
        $x_10_4 = "verif" wide //weight: 10
        $x_1_5 = "- ray" wide //weight: 1
        $x_1_6 = "- recaptcha" wide //weight: 1
        $x_1_7 = "- re captcha" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DF_2147932251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DF!MTB"
        threat_id = "2147932251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_10_2 = "verif" wide //weight: 10
        $x_5_3 = "http:" wide //weight: 5
        $x_5_4 = "https_" wide //weight: 5
        $x_1_5 = "- recaptcha" wide //weight: 1
        $x_1_6 = "- re captcha" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_J_2147932433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.J!MTB"
        threat_id = "2147932433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http" wide //weight: 10
        $x_10_2 = "mshta" wide //weight: 10
        $x_10_3 = "captcha" wide //weight: 10
        $x_10_4 = "verif" wide //weight: 10
        $x_1_5 = ".mp4" wide //weight: 1
        $x_1_6 = ".mp3" wide //weight: 1
        $x_1_7 = ".flv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DD_2147932646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DD!MTB"
        threat_id = "2147932646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "verif" wide //weight: 10
        $x_10_4 = "\\1" wide //weight: 10
        $x_1_5 = "robot - captcha" wide //weight: 1
        $x_1_6 = "robot: captcha" wide //weight: 1
        $x_1_7 = "- ray" wide //weight: 1
        $x_1_8 = "- recaptcha" wide //weight: 1
        $x_1_9 = "- re captcha" wide //weight: 1
        $x_1_10 = "robot: r" wide //weight: 1
        $x_1_11 = "robot - r" wide //weight: 1
        $x_1_12 = "- rCAPTCHA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DE_2147932647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DE!MTB"
        threat_id = "2147932647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "\\1" wide //weight: 10
        $x_10_4 = "verif" wide //weight: 10
        $x_1_5 = "robot - captcha" wide //weight: 1
        $x_1_6 = "robot: captcha" wide //weight: 1
        $x_1_7 = "- ray" wide //weight: 1
        $x_1_8 = "- recaptcha" wide //weight: 1
        $x_1_9 = "- re captcha" wide //weight: 1
        $x_1_10 = "robot: r" wide //weight: 1
        $x_1_11 = "robot - r" wide //weight: 1
        $x_1_12 = "- rCAPTCHA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_L_2147932742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.L!MTB"
        threat_id = "2147932742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http" wide //weight: 1
        $x_1_2 = "mshta" wide //weight: 1
        $x_1_3 = "captcha" wide //weight: 1
        $x_1_4 = "verif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_M_2147932743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.M!MTB"
        threat_id = "2147932743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "-command $" wide //weight: 10
        $x_10_3 = ".Content; iex $" wide //weight: 10
        $x_1_4 = "Invoke-WebRequest -Uri $" wide //weight: 1
        $x_1_5 = "iwr -Uri $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DH_2147932752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DH!MTB"
        threat_id = "2147932752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "|Member|Where-Object{$_.Name -like" wide //weight: 1
        $x_1_3 = ".Name).Invoke" wide //weight: 1
        $x_1_4 = "CommandTypes]::Cmdlet" wide //weight: 1
        $x_1_5 = {76 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 3a 00 2f 00 [0-15] 27 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_O_2147933213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.O!MTB"
        threat_id = "2147933213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 2d 00 65 00}  //weight: 10, accuracy: Low
        $x_1_2 = "iwr" wide //weight: 1
        $x_1_3 = "invoke-webrequest" wide //weight: 1
        $x_1_4 = "iex" wide //weight: 1
        $x_1_5 = "invoke-expression" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_Y_2147933215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.Y!MTB"
        threat_id = "2147933215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 68 00 73 00 74 00 61 00 [0-32] 68 00 74 00 74 00 70 00 [0-80] 23 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

