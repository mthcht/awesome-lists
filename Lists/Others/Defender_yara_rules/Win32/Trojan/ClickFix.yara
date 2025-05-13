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
        $n_1000_6 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_7 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
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
        $x_1_5 = " ray" wide //weight: 1
        $x_1_6 = " recaptcha" wide //weight: 1
        $x_1_7 = "Press Enter" wide //weight: 1
        $x_1_8 = " re captcha" wide //weight: 1
        $x_1_9 = " rCAPTCHA" wide //weight: 1
        $x_1_10 = " clip FREE" wide //weight: 1
        $x_1_11 = " Over FREE" wide //weight: 1
        $x_1_12 = "robot: r" wide //weight: 1
        $x_1_13 = "robot - r" wide //weight: 1
        $x_1_14 = "robot - Cloudflare" wide //weight: 1
        $x_1_15 = "robot: Cloudflare" wide //weight: 1
        $x_1_16 = "robot: CAPTCHA" wide //weight: 1
        $x_1_17 = "robot - CAPTCHA" wide //weight: 1
        $x_1_18 = "Human - r" wide //weight: 1
        $x_1_19 = "Human: r" wide //weight: 1
        $x_1_20 = "Human: CAPTCHA" wide //weight: 1
        $x_1_21 = "Human - CAPTCHA" wide //weight: 1
        $x_1_22 = "Microsoft Windows: Fix Internet DNS Service reconnect" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 11 of ($x_1_*))) or
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
        $x_1_5 = " ray" wide //weight: 1
        $x_1_6 = " recaptcha" wide //weight: 1
        $x_1_7 = "Press Enter" wide //weight: 1
        $x_1_8 = " re captcha" wide //weight: 1
        $x_1_9 = " rCAPTCHA" wide //weight: 1
        $x_1_10 = " clip FREE" wide //weight: 1
        $x_1_11 = " Over FREE" wide //weight: 1
        $x_1_12 = "robot: r" wide //weight: 1
        $x_1_13 = "robot - r" wide //weight: 1
        $x_1_14 = "robot - Cloudflare" wide //weight: 1
        $x_1_15 = "robot: Cloudflare" wide //weight: 1
        $x_1_16 = "robot: CAPTCHA" wide //weight: 1
        $x_1_17 = "robot - CAPTCHA" wide //weight: 1
        $x_1_18 = "Human - r" wide //weight: 1
        $x_1_19 = "Human: r" wide //weight: 1
        $x_1_20 = "Human: CAPTCHA" wide //weight: 1
        $x_1_21 = "Human - CAPTCHA" wide //weight: 1
        $x_1_22 = "Microsoft Windows: Fix Internet DNS Service reconnect" wide //weight: 1
        $n_1000_23 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_24 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_5_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
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
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "verif" wide //weight: 10
        $x_1_4 = " ray" wide //weight: 1
        $x_1_5 = " recaptcha" wide //weight: 1
        $x_1_6 = " re captcha" wide //weight: 1
        $x_1_7 = "Press Enter" wide //weight: 1
        $x_1_8 = " rCAPTCHA" wide //weight: 1
        $x_1_9 = " clip FREE" wide //weight: 1
        $x_1_10 = " Over FREE" wide //weight: 1
        $x_1_11 = "robot: r" wide //weight: 1
        $x_1_12 = "robot - r" wide //weight: 1
        $x_1_13 = "robot - Cloudflare" wide //weight: 1
        $x_1_14 = "robot: Cloudflare" wide //weight: 1
        $x_1_15 = "robot: CAPTCHA" wide //weight: 1
        $x_1_16 = "robot - CAPTCHA" wide //weight: 1
        $x_1_17 = "Human - r" wide //weight: 1
        $x_1_18 = "Human: r" wide //weight: 1
        $x_1_19 = "Human: CAPTCHA" wide //weight: 1
        $x_1_20 = "Human - CAPTCHA" wide //weight: 1
        $x_1_21 = "Microsoft Windows: Fix Internet DNS Service reconnect" wide //weight: 1
        $n_100_22 = "msedgewebview2.exe" wide //weight: -100
        $n_1000_23 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
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
        $x_1_5 = " ray" wide //weight: 1
        $x_1_6 = " recaptcha" wide //weight: 1
        $x_1_7 = " re captcha" wide //weight: 1
        $x_1_8 = " rCAPTCHA" wide //weight: 1
        $x_1_9 = " clip FREE" wide //weight: 1
        $x_1_10 = " Over FREE" wide //weight: 1
        $x_1_11 = "Press Enter" wide //weight: 1
        $x_1_12 = "robot: r" wide //weight: 1
        $x_1_13 = "robot - r" wide //weight: 1
        $x_1_14 = "robot - Cloudflare" wide //weight: 1
        $x_1_15 = "robot: Cloudflare" wide //weight: 1
        $x_1_16 = "robot: CAPTCHA" wide //weight: 1
        $x_1_17 = "robot - CAPTCHA" wide //weight: 1
        $x_1_18 = "Human - r" wide //weight: 1
        $x_1_19 = "Human: r" wide //weight: 1
        $x_1_20 = "Human: CAPTCHA" wide //weight: 1
        $x_1_21 = "Human - CAPTCHA" wide //weight: 1
        $x_1_22 = "Microsoft Windows: Fix Internet DNS Service reconnect" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 11 of ($x_1_*))) or
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
        $n_100_5 = "msedgewebview2.exe" wide //weight: -100
        $n_1000_6 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
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
        threshold = "311"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_100_2 = "-command $" wide //weight: 100
        $x_100_3 = "http" wide //weight: 100
        $x_10_4 = {2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 3b 00 [0-32] 24 00}  //weight: 10, accuracy: Low
        $x_1_5 = "invoke-webRequest -uri $" wide //weight: 1
        $x_1_6 = "iwr -uri $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
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
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = ".Name).Invoke" wide //weight: 10
        $x_10_3 = "CommandTypes]::Cmdlet" wide //weight: 10
        $x_10_4 = {76 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 3a 00 [0-15] 27 00 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_1_5 = "|Member|Where-Object{$_.Name -like" wide //weight: 1
        $x_1_6 = {67 00 65 00 74 00 2d 00 6d 00 65 00 6d 00 62 00 65 00 72 00 29 00 7c 00 77 00 68 00 65 00 72 00 65 00 7b 00 28 00 [0-15] 29 00 2e 00 76 00 61 00 6c 00 75 00 65 00 2e 00 6e 00 61 00 6d 00 65 00 2d 00 63 00 6c 00 69 00 6b 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
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

rule Trojan_Win32_ClickFix_MB_2147933575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.MB!MTB"
        threat_id = "2147933575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = "- CAPTCHA" wide //weight: 1
        $x_1_4 = "Verif" wide //weight: 1
        $x_1_5 = "robot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_MA_2147933576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.MA!MTB"
        threat_id = "2147933576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "-NoProfile" wide //weight: 2
        $x_2_3 = "mshta" wide //weight: 2
        $x_1_4 = "https://" wide //weight: 1
        $x_1_5 = {43 00 41 00 50 00 54 00 43 00 48 00 41 00 14 00 72 00}  //weight: 1, accuracy: Low
        $x_1_6 = "Verif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_MD_2147933729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.MD!MTB"
        threat_id = "2147933729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "https" wide //weight: 1
        $x_1_3 = "Invoke-CimMethod" wide //weight: 1
        $x_1_4 = "Win32_Process" wide //weight: 1
        $x_1_5 = "Create" wide //weight: 1
        $x_1_6 = "-Arguments" wide //weight: 1
        $x_2_7 = "ms' + 'hta' + '.exe" wide //weight: 2
        $x_1_8 = "CAPTCHA" wide //weight: 1
        $x_1_9 = "Verif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_AB_2147933821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AB!MTB"
        threat_id = "2147933821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "71"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "http" wide //weight: 20
        $x_20_2 = "mshta" wide //weight: 20
        $x_20_3 = "\\1" wide //weight: 20
        $x_10_4 = ".shop" wide //weight: 10
        $x_10_5 = ".hair" wide //weight: 10
        $x_10_6 = ".cyou" wide //weight: 10
        $x_10_7 = ".click" wide //weight: 10
        $x_1_8 = ".mp" wide //weight: 1
        $x_1_9 = ".flv" wide //weight: 1
        $n_1000_10 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_11 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_20_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*) and 4 of ($x_10_*))) or
            ((3 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DQ_2147933822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DQ!MTB"
        threat_id = "2147933822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "-replace" wide //weight: 10
        $x_10_3 = "verif" wide //weight: 10
        $x_1_4 = " ray" wide //weight: 1
        $x_1_5 = " recaptcha" wide //weight: 1
        $x_1_6 = " re captcha" wide //weight: 1
        $x_1_7 = " rCAPTCHA" wide //weight: 1
        $x_1_8 = "Press Enter" wide //weight: 1
        $x_1_9 = " clip FREE" wide //weight: 1
        $x_1_10 = " Over FREE" wide //weight: 1
        $x_1_11 = "robot: r" wide //weight: 1
        $x_1_12 = "robot - r" wide //weight: 1
        $x_1_13 = "robot - Cloudflare" wide //weight: 1
        $x_1_14 = "robot: Cloudflare" wide //weight: 1
        $x_1_15 = "robot: CAPTCHA" wide //weight: 1
        $x_1_16 = "robot - CAPTCHA" wide //weight: 1
        $x_1_17 = "Human - r" wide //weight: 1
        $x_1_18 = "Human: r" wide //weight: 1
        $x_1_19 = "Human: CAPTCHA" wide //weight: 1
        $x_1_20 = "Human - CAPTCHA" wide //weight: 1
        $x_1_21 = "Microsoft Windows: Fix Internet DNS Service reconnect" wide //weight: 1
        $x_1_22 = "Restart DNS service in the Microsoft Windows system" wide //weight: 1
        $x_1_23 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_24 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_25 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_26 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 1, accuracy: High
        $x_1_27 = {48 00 75 00 6d 00 30 04 6e 00 [0-30] 21 04 41 00 50 00 54 00 43 00 48 00 41 00}  //weight: 1, accuracy: Low
        $x_1_28 = {21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_29 = {99 03 20 00 61 00 6d 00 20 00 6e 00 bf 03 74 00}  //weight: 1, accuracy: High
        $x_1_30 = {52 00 bf 03 62 00 bf 03 74 00}  //weight: 1, accuracy: High
        $x_1_31 = {60 21 51 02 6d 00 78 05 85 05 74 00}  //weight: 1, accuracy: High
        $x_1_32 = {7e 02 85 05 62 00 85 05 74 00}  //weight: 1, accuracy: High
        $x_1_33 = {f9 03 91 03 a1 03 a4 03 43 00 48 00 41 00}  //weight: 1, accuracy: High
        $x_1_34 = {43 00 41 00 a1 03 54 00 43 00 48 00 41 00}  //weight: 1, accuracy: High
        $x_1_35 = {72 00 6f 00 84 01 6f 00 74 00}  //weight: 1, accuracy: High
        $x_1_36 = {72 00 bf 03 62 00 bf 03 c4 03}  //weight: 1, accuracy: High
        $x_1_37 = {43 00 91 03 50 00 a4 03 43 00 97 03 91 03}  //weight: 1, accuracy: High
        $x_1_38 = {21 04 91 03 20 04 03 a4 21 04 1d 04 91 03}  //weight: 1, accuracy: High
        $x_1_39 = {56 00 35 04 72 00 56 04 66 00}  //weight: 1, accuracy: High
        $x_1_40 = {21 04 91 03 20 04 22 04 21 04 1d 04 41 00}  //weight: 1, accuracy: High
        $x_1_41 = {72 00 3e 04 62 00 3e 04 74 00}  //weight: 1, accuracy: High
        $x_1_42 = {43 00 41 00 50 00 54 00 43 00 97 03 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((31 of ($x_1_*))) or
            ((1 of ($x_10_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_SA_2147934466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SA"
        threat_id = "2147934466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = {20 00 05 27 20 00}  //weight: 10, accuracy: High
        $x_10_3 = {20 00 14 27 20 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_ClickFix_AC_2147934651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AC!MTB"
        threat_id = "2147934651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[convert]::tobase64string($" wide //weight: 1
        $x_1_2 = ".invoke($" wide //weight: 1
        $x_1_3 = "net.webclient" wide //weight: 1
        $x_1_4 = "http" wide //weight: 1
        $x_1_5 = ".getstring($" wide //weight: 1
        $x_1_6 = "[system.reflection.assembly]::load($" wide //weight: 1
        $x_1_7 = ".getmethod" wide //weight: 1
        $x_1_8 = ".download" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_AG_2147934652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AG!MTB"
        threat_id = "2147934652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_200_1 = "powershell" wide //weight: 200
        $x_1_2 = "captcha" wide //weight: 1
        $x_1_3 = "robot" wide //weight: 1
        $x_1_4 = "human" wide //weight: 1
        $x_1_5 = "Press Enter" wide //weight: 1
        $x_1_6 = " ray" wide //weight: 1
        $x_1_7 = " recaptcha" wide //weight: 1
        $x_1_8 = " re captcha" wide //weight: 1
        $x_1_9 = " rCAPTCHA" wide //weight: 1
        $x_1_10 = " clip FREE" wide //weight: 1
        $x_1_11 = " Over FREE" wide //weight: 1
        $x_1_12 = "robot: r" wide //weight: 1
        $x_1_13 = "robot - r" wide //weight: 1
        $x_1_14 = "Cloudflare" wide //weight: 1
        $x_1_15 = "- Over FREE" wide //weight: 1
        $x_1_16 = "Google Meet" wide //weight: 1
        $x_1_17 = "DNS service" wide //weight: 1
        $x_1_18 = "filtered by CF" wide //weight: 1
        $x_1_19 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_20 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_21 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_22 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 1, accuracy: High
        $x_1_23 = {48 00 75 00 6d 00 30 04 6e 00 [0-30] 21 04 41 00 50 00 54 00 43 00 48 00 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_AH_2147934653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AH!MTB"
        threat_id = "2147934653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "410"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_100_2 = "curl" wide //weight: 100
        $x_100_3 = "-join" wide //weight: 100
        $x_100_4 = "[char]($" wide //weight: 100
        $x_10_5 = "invoke-expression" wide //weight: 10
        $x_10_6 = "iex" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ME_2147935170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ME!MTB"
        threat_id = "2147935170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PowerShell.exe -w 1 & \\W" wide //weight: 1
        $x_2_2 = "m*ht*e https://" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_MF_2147935171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.MF!MTB"
        threat_id = "2147935171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c start /min" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = {24 00 70 00 61 00 74 00 68 00 3d 00 27 00 63 00 3a 00 [0-69] 2e 00 6d 00 73 00 69 00}  //weight: 1, accuracy: Low
        $x_1_4 = "-NoProfile" wide //weight: 1
        $x_1_5 = "-WindowStyle" wide //weight: 1
        $x_1_6 = "Hidden" wide //weight: 1
        $x_1_7 = "-Command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_AP_2147935190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AP!MTB"
        threat_id = "2147935190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http" wide //weight: 10
        $x_10_2 = "powershell" wide //weight: 10
        $x_10_3 = ".content" wide //weight: 10
        $x_10_4 = "captcha" wide //weight: 10
        $x_10_5 = "Press Enter" wide //weight: 10
        $x_1_6 = "iex" wide //weight: 1
        $x_1_7 = "invoke-expression" wide //weight: 1
        $x_1_8 = "invoke-webrequest" wide //weight: 1
        $x_1_9 = "iwr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DV_2147935276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DV!MTB"
        threat_id = "2147935276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_1_2 = "http" wide //weight: 1
        $x_100_3 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_4 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_5 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_6 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 100, accuracy: High
        $x_100_7 = {48 00 75 00 6d 00 30 04 6e 00 [0-30] 21 04 41 00 50 00 54 00 43 00 48 00 41 00}  //weight: 100, accuracy: Low
        $x_100_8 = {21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_9 = {99 03 20 00 61 00 6d 00 20 00 6e 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_10 = {52 00 bf 03 62 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_11 = {60 21 51 02 6d 00 78 05 85 05 74 00}  //weight: 100, accuracy: High
        $x_100_12 = {7e 02 85 05 62 00 85 05 74 00}  //weight: 100, accuracy: High
        $x_100_13 = {f9 03 91 03 a1 03 a4 03 43 00 48 00 41 00}  //weight: 100, accuracy: High
        $x_100_14 = {72 00 0b 20 6f 00 62 00 6f 00 0d 20 74 00}  //weight: 100, accuracy: High
        $x_100_15 = {56 00 65 00 72 00 56 04 66 00 56 04 63 00 30 04 74 00 56 04 bf 03 78 05}  //weight: 100, accuracy: High
        $x_100_16 = {43 00 41 00 a1 03 54 00 43 00 48 00 41 00}  //weight: 100, accuracy: High
        $x_100_17 = {72 00 6f 00 84 01 6f 00 74 00}  //weight: 100, accuracy: High
        $x_100_18 = {72 00 bf 03 62 00 bf 03 c4 03}  //weight: 100, accuracy: High
        $x_100_19 = {43 00 91 03 50 00 a4 03 43 00 97 03 91 03}  //weight: 100, accuracy: High
        $x_100_20 = {21 04 91 03 20 04 03 a4 21 04 1d 04 91 03}  //weight: 100, accuracy: High
        $x_100_21 = {56 00 35 04 72 00 56 04 66 00}  //weight: 100, accuracy: High
        $x_100_22 = {21 04 91 03 20 04 22 04 21 04 1d 04 41 00}  //weight: 100, accuracy: High
        $x_100_23 = {72 00 3e 04 62 00 3e 04 74 00}  //weight: 100, accuracy: High
        $x_100_24 = {43 00 41 00 50 00 54 00 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_25 = {9d 03 bf 03 6e 00 2d 00 62 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_26 = {68 00 c5 03 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_27 = {35 04 72 00 56 04 66 00 56 04 35 04 64 00}  //weight: 100, accuracy: High
        $x_100_28 = {21 04 6c 00 3e 04 75 00 64 00}  //weight: 100, accuracy: High
        $x_100_29 = {7e 02 80 05 62 00 80 05 1f 1d}  //weight: 100, accuracy: High
        $x_100_30 = {33 04 bf 03 62 00 3e 04 74 00}  //weight: 100, accuracy: High
        $x_100_31 = {1d 04 75 00 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_32 = {21 04 10 04 20 04 22 04 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_33 = {21 04 10 04 50 00 54 00 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_34 = {21 04 10 04 20 04 22 04 43 00 48 00 41 00}  //weight: 100, accuracy: High
        $x_100_35 = {56 00 35 04 72 00 69 00 66 00}  //weight: 100, accuracy: High
        $x_100_36 = {1d 04 c5 03 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_37 = {f9 03 91 03 20 04 22 04 21 04 1d 04 91 03}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_AO_2147935373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AO!MTB"
        threat_id = "2147935373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "421"
        strings_accuracy = "Low"
    strings:
        $x_200_1 = "mshta" wide //weight: 200
        $x_200_2 = "http" wide //weight: 200
        $x_20_3 = ".mp" wide //weight: 20
        $x_20_4 = ".flv" wide //weight: 20
        $x_20_5 = ".mdb" wide //weight: 20
        $x_20_6 = ".eps" wide //weight: 20
        $x_20_7 = ".dat" wide //weight: 20
        $x_20_8 = ".cda" wide //weight: 20
        $x_20_9 = ".m4a" wide //weight: 20
        $x_20_10 = ".xll" wide //weight: 20
        $x_1_11 = "captcha" wide //weight: 1
        $x_1_12 = "robot" wide //weight: 1
        $x_1_13 = "human" wide //weight: 1
        $x_1_14 = " ray" wide //weight: 1
        $x_1_15 = " recaptcha" wide //weight: 1
        $x_1_16 = " re captcha" wide //weight: 1
        $x_1_17 = " rCAPTCHA" wide //weight: 1
        $x_1_18 = " clip FREE" wide //weight: 1
        $x_1_19 = " Over FREE" wide //weight: 1
        $x_1_20 = "Press Enter" wide //weight: 1
        $x_1_21 = "robot: r" wide //weight: 1
        $x_1_22 = "robot - r" wide //weight: 1
        $x_1_23 = "Cloudflare" wide //weight: 1
        $x_1_24 = "- Over FREE" wide //weight: 1
        $x_1_25 = "Google Meet" wide //weight: 1
        $x_1_26 = "DNS service" wide //weight: 1
        $x_1_27 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_28 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_29 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_30 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 1, accuracy: High
        $x_1_31 = {48 00 75 00 6d 00 30 04 6e 00 [0-30] 21 04 41 00 50 00 54 00 43 00 48 00 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_200_*) and 21 of ($x_1_*))) or
            ((2 of ($x_200_*) and 1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_200_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DW_2147935377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DW!MTB"
        threat_id = "2147935377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "66"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_1_2 = "http" wide //weight: 1
        $x_5_3 = "verif" wide //weight: 5
        $x_5_4 = "\\1" wide //weight: 5
        $x_50_5 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 50, accuracy: High
        $x_50_6 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 50, accuracy: High
        $x_50_7 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 50, accuracy: High
        $x_50_8 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 50, accuracy: High
        $x_50_9 = {48 00 75 00 6d 00 30 04 6e 00}  //weight: 50, accuracy: High
        $x_50_10 = {21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 50, accuracy: High
        $x_50_11 = {99 03 20 00 61 00 6d 00 20 00 6e 00 bf 03 74 00}  //weight: 50, accuracy: High
        $x_50_12 = {52 00 bf 03 62 00 bf 03 74 00}  //weight: 50, accuracy: High
        $x_50_13 = {60 21 51 02 6d 00 78 05 85 05 74 00}  //weight: 50, accuracy: High
        $x_50_14 = {7e 02 85 05 62 00 85 05 74 00}  //weight: 50, accuracy: High
        $x_50_15 = {f9 03 91 03 a1 03 a4 03 43 00 48 00 41 00}  //weight: 50, accuracy: High
        $x_50_16 = {72 00 0b 20 6f 00 62 00 6f 00 0d 20 74 00}  //weight: 50, accuracy: High
        $x_50_17 = {43 00 41 00 a1 03 54 00 43 00 48 00 41 00}  //weight: 50, accuracy: High
        $x_50_18 = {72 00 6f 00 84 01 6f 00 74 00}  //weight: 50, accuracy: High
        $x_50_19 = {72 00 bf 03 62 00 bf 03 c4 03}  //weight: 50, accuracy: High
        $x_50_20 = {43 00 91 03 50 00 a4 03 43 00 97 03 91 03}  //weight: 50, accuracy: High
        $x_50_21 = {21 04 91 03 20 04 03 a4 21 04 1d 04 91 03}  //weight: 50, accuracy: High
        $x_50_22 = {21 04 91 03 20 04 22 04 21 04 1d 04 41 00}  //weight: 50, accuracy: High
        $x_50_23 = {72 00 3e 04 62 00 3e 04 74 00}  //weight: 50, accuracy: High
        $x_50_24 = {43 00 41 00 50 00 54 00 43 00 97 03 41 00}  //weight: 50, accuracy: High
        $x_50_25 = {68 00 c5 03 6d 00 30 04 6e 00}  //weight: 50, accuracy: High
        $x_50_26 = {21 04 6c 00 3e 04 75 00 64 00}  //weight: 50, accuracy: High
        $x_50_27 = {7e 02 80 05 62 00 80 05 1f 1d}  //weight: 50, accuracy: High
        $x_50_28 = {33 04 bf 03 62 00 3e 04 74 00}  //weight: 50, accuracy: High
        $x_50_29 = {1d 04 75 00 6d 00 30 04 6e 00}  //weight: 50, accuracy: High
        $x_50_30 = {21 04 10 04 20 04 22 04 43 00 97 03 41 00}  //weight: 50, accuracy: High
        $x_50_31 = {21 04 10 04 50 00 54 00 43 00 97 03 41 00}  //weight: 50, accuracy: High
        $x_50_32 = {1d 04 c5 03 6d 00 30 04 6e 00}  //weight: 50, accuracy: High
        $x_50_33 = {f9 03 91 03 20 04 22 04 21 04 1d 04 91 03}  //weight: 50, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_AN_2147935503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AN!MTB"
        threat_id = "2147935503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "new-object" wide //weight: 10
        $x_10_2 = "powershell" wide //weight: 10
        $x_10_3 = "wscript.shell" wide //weight: 10
        $x_10_4 = "http" wide //weight: 10
        $x_1_5 = ".sendkeys" wide //weight: 1
        $x_1_6 = " iex" wide //weight: 1
        $x_1_7 = "invoke-expression" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZA_2147936037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZA!MTB"
        threat_id = "2147936037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-split($" wide //weight: 1
        $x_1_3 = "-replace" wide //weight: 1
        $x_1_4 = "0x$" wide //weight: 1
        $x_1_5 = "byte" wide //weight: 1
        $x_1_6 = "join" wide //weight: 1
        $x_1_7 = "substring" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZB_2147936038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZB!MTB"
        threat_id = "2147936038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "curl" wide //weight: 1
        $x_1_3 = "start-process" wide //weight: 1
        $x_1_4 = "cscript" wide //weight: 1
        $x_1_5 = "verif" wide //weight: 1
        $x_1_6 = "Join-Path $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DS_2147936340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DS!MTB"
        threat_id = "2147936340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell" wide //weight: 5
        $x_20_2 = "+'://'+" wide //weight: 20
        $x_5_3 = "[System.Text.Encoding]::UTF8.GetString($" wide //weight: 5
        $x_5_4 = ".Content)" wide //weight: 5
        $x_1_5 = "irm" wide //weight: 1
        $x_1_6 = "invoke-restmethod" wide //weight: 1
        $x_1_7 = "iwr" wide //weight: 1
        $x_1_8 = "invoke-webrequest" wide //weight: 1
        $x_1_9 = "iex" wide //weight: 1
        $x_1_10 = "invoke-expresssion" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DU_2147936341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DU!MTB"
        threat_id = "2147936341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "57"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-split($" wide //weight: 1
        $x_1_3 = "-replace" wide //weight: 1
        $x_50_4 = "0x$&" wide //weight: 50
        $x_1_5 = "-join" wide //weight: 1
        $x_1_6 = "byte[]]::new(" wide //weight: 1
        $x_1_7 = ".TransformFinalBlock($" wide //weight: 1
        $x_1_8 = ".Substring(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DX_2147936522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DX!MTB"
        threat_id = "2147936522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "132"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_1_2 = "irm" wide //weight: 1
        $x_1_3 = "Invoke-RestMethod" wide //weight: 1
        $x_1_4 = "iwr" wide //weight: 1
        $x_1_5 = "Invoke-WebRequest" wide //weight: 1
        $x_1_6 = "iex" wide //weight: 1
        $x_1_7 = "Invoke-Expression" wide //weight: 1
        $x_20_8 = "verif" wide //weight: 20
        $x_100_9 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_10 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_11 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_12 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 100, accuracy: High
        $x_100_13 = {48 00 75 00 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_14 = "CIoudfIare Unique One-time" wide //weight: 100
        $x_100_15 = {21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_16 = {99 03 20 00 61 00 6d 00 20 00 6e 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_17 = {52 00 bf 03 62 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_18 = {60 21 51 02 6d 00 78 05 85 05 74 00}  //weight: 100, accuracy: High
        $x_100_19 = {7e 02 85 05 62 00 85 05 74 00}  //weight: 100, accuracy: High
        $x_100_20 = {f9 03 91 03 a1 03 a4 03 43 00 48 00 41 00}  //weight: 100, accuracy: High
        $x_100_21 = {72 00 0b 20 6f 00 62 00 6f 00 0d 20 74 00}  //weight: 100, accuracy: High
        $x_100_22 = {43 00 41 00 a1 03 54 00 43 00 48 00 41 00}  //weight: 100, accuracy: High
        $x_100_23 = {72 00 6f 00 84 01 6f 00 74 00}  //weight: 100, accuracy: High
        $x_100_24 = {72 00 bf 03 62 00 bf 03 c4 03}  //weight: 100, accuracy: High
        $x_100_25 = {43 00 91 03 50 00 a4 03 43 00 97 03 91 03}  //weight: 100, accuracy: High
        $x_100_26 = {21 04 91 03 20 04 03 a4 21 04 1d 04 91 03}  //weight: 100, accuracy: High
        $x_100_27 = {21 04 91 03 20 04 22 04 21 04 1d 04 41 00}  //weight: 100, accuracy: High
        $x_100_28 = {72 00 3e 04 62 00 3e 04 74 00}  //weight: 100, accuracy: High
        $x_100_29 = {43 00 41 00 50 00 54 00 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_30 = {9d 03 bf 03 6e 00 2d 00 62 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_31 = {68 00 c5 03 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_32 = {35 04 72 00 56 04 66 00 56 04 35 04 64 00}  //weight: 100, accuracy: High
        $x_100_33 = {21 04 6c 00 3e 04 75 00 64 00}  //weight: 100, accuracy: High
        $x_100_34 = {7e 02 80 05 62 00 80 05 1f 1d}  //weight: 100, accuracy: High
        $x_100_35 = {33 04 bf 03 62 00 3e 04 74 00}  //weight: 100, accuracy: High
        $x_100_36 = {1d 04 75 00 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_37 = {21 04 10 04 20 04 22 04 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_38 = {21 04 10 04 50 00 54 00 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_39 = {1d 04 c5 03 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_40 = {f9 03 91 03 20 04 22 04 21 04 1d 04 91 03}  //weight: 100, accuracy: High
        $n_1000_41 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_42 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DZ_2147936523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DZ!MTB"
        threat_id = "2147936523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "106"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "mshta" wide //weight: 5
        $x_1_2 = "http" wide //weight: 1
        $x_100_3 = {99 03 20 00 61 00 6d 00 20 00 6e 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_4 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_5 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_6 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_7 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 100, accuracy: High
        $x_100_8 = {48 00 75 00 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_9 = "CIoudfIare Unique One-time" wide //weight: 100
        $x_100_10 = {21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_11 = {52 00 bf 03 62 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_12 = {60 21 51 02 6d 00 78 05 85 05 74 00}  //weight: 100, accuracy: High
        $x_100_13 = {7e 02 85 05 62 00 85 05 74 00}  //weight: 100, accuracy: High
        $x_100_14 = {f9 03 91 03 a1 03 a4 03 43 00 48 00 41 00}  //weight: 100, accuracy: High
        $x_100_15 = {56 00 65 00 72 00 56 04 66 00 56 04 63 00 30 04 74 00 56 04 bf 03 78 05}  //weight: 100, accuracy: High
        $x_100_16 = {72 00 0b 20 6f 00 62 00 6f 00 0d 20 74 00}  //weight: 100, accuracy: High
        $x_100_17 = {43 00 41 00 a1 03 54 00 43 00 48 00 41 00}  //weight: 100, accuracy: High
        $x_100_18 = {72 00 6f 00 84 01 6f 00 74 00}  //weight: 100, accuracy: High
        $x_100_19 = {72 00 bf 03 62 00 bf 03 c4 03}  //weight: 100, accuracy: High
        $x_100_20 = {43 00 91 03 50 00 a4 03 43 00 97 03 91 03}  //weight: 100, accuracy: High
        $x_100_21 = {21 04 91 03 20 04 03 a4 21 04 1d 04 91 03}  //weight: 100, accuracy: High
        $x_100_22 = {56 00 35 04 72 00 56 04 66 00}  //weight: 100, accuracy: High
        $x_100_23 = {21 04 91 03 20 04 22 04 21 04 1d 04 41 00}  //weight: 100, accuracy: High
        $x_100_24 = {72 00 3e 04 62 00 3e 04 74 00}  //weight: 100, accuracy: High
        $x_100_25 = {43 00 41 00 50 00 54 00 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_26 = {9d 03 bf 03 6e 00 2d 00 62 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_27 = {68 00 c5 03 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_28 = {35 04 72 00 56 04 66 00 56 04 35 04 64 00}  //weight: 100, accuracy: High
        $x_100_29 = {21 04 6c 00 3e 04 75 00 64 00}  //weight: 100, accuracy: High
        $x_100_30 = {7e 02 80 05 62 00 80 05 1f 1d}  //weight: 100, accuracy: High
        $x_100_31 = {33 04 bf 03 62 00 3e 04 74 00}  //weight: 100, accuracy: High
        $x_100_32 = {1d 04 75 00 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_33 = {21 04 10 04 20 04 22 04 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_34 = {21 04 10 04 50 00 54 00 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_35 = {21 04 10 04 20 04 22 04 43 00 48 00 41 00}  //weight: 100, accuracy: High
        $x_100_36 = {56 00 35 04 72 00 69 00 66 00}  //weight: 100, accuracy: High
        $x_100_37 = {1d 04 c5 03 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_38 = {f9 03 91 03 20 04 22 04 21 04 1d 04 91 03}  //weight: 100, accuracy: High
        $n_1000_39 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_40 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_AJ_2147936895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AJ!MTB"
        threat_id = "2147936895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "net.sockets.tcpclient(" wide //weight: 10
        $x_10_3 = "net.webclient" wide //weight: 10
        $x_10_4 = ";while($" wide //weight: 10
        $x_10_5 = ").connected" wide //weight: 10
        $x_1_6 = ".downloadfile(" wide //weight: 1
        $x_1_7 = ".ps1; exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_AQ_2147936896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AQ!MTB"
        threat_id = "2147936896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2051"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".mp" wide //weight: 1
        $x_1_2 = ".flv" wide //weight: 1
        $x_1_3 = ".mdb" wide //weight: 1
        $x_1_4 = ".eps" wide //weight: 1
        $x_1_5 = ".dat" wide //weight: 1
        $x_1_6 = ".cda" wide //weight: 1
        $x_1_7 = ".m4a" wide //weight: 1
        $x_1_8 = ".xll" wide //weight: 1
        $x_2000_9 = "powershell" wide //weight: 2000
        $x_50_10 = "captcha" wide //weight: 50
        $x_50_11 = "Press Enter" wide //weight: 50
        $x_50_12 = "robot" wide //weight: 50
        $x_50_13 = "human" wide //weight: 50
        $x_50_14 = " ray" wide //weight: 50
        $x_50_15 = " recaptcha" wide //weight: 50
        $x_50_16 = " re captcha" wide //weight: 50
        $x_50_17 = " rCAPTCHA" wide //weight: 50
        $x_50_18 = " clip FREE" wide //weight: 50
        $x_50_19 = " Over FREE" wide //weight: 50
        $x_50_20 = "robot: r" wide //weight: 50
        $x_50_21 = "robot - r" wide //weight: 50
        $x_50_22 = "Cloudflare" wide //weight: 50
        $x_50_23 = "- Over FREE" wide //weight: 50
        $x_50_24 = "Google Meet" wide //weight: 50
        $x_50_25 = "DNS service" wide //weight: 50
        $x_50_26 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 50, accuracy: High
        $x_50_27 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 50, accuracy: High
        $x_50_28 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 50, accuracy: High
        $x_50_29 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 50, accuracy: High
        $x_50_30 = {48 00 75 00 6d 00 30 04 6e 00 [0-30] 21 04 41 00 50 00 54 00 43 00 48 00 41 00}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2000_*) and 1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((1 of ($x_2000_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_AF_2147937004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AF!MTB"
        threat_id = "2147937004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "212"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "http" wide //weight: 100
        $x_100_2 = "powershell" wide //weight: 100
        $x_10_3 = ":FromBase64String($" wide //weight: 10
        $x_10_4 = ".content" wide //weight: 10
        $x_10_5 = "start" wide //weight: 10
        $x_10_6 = "curl" wide //weight: 10
        $x_10_7 = "-Encoded" wide //weight: 10
        $x_1_8 = "iex" wide //weight: 1
        $x_1_9 = "invoke-expression" wide //weight: 1
        $x_1_10 = "invoke-webrequest" wide //weight: 1
        $x_1_11 = "iwr" wide //weight: 1
        $x_1_12 = "irm" wide //weight: 1
        $x_1_13 = "invoke-restmethod" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_AI_2147937005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AI!MTB"
        threat_id = "2147937005"
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
        $x_10_2 = "net.sockets.tcpclient(" wide //weight: 10
        $x_10_3 = ".getstream" wide //weight: 10
        $x_10_4 = "[byte[]]$" wide //weight: 10
        $x_1_5 = ".streamwriter($" wide //weight: 1
        $x_1_6 = ".read($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_AK_2147937006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AK!MTB"
        threat_id = "2147937006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wscript.shell" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = ".sendKeys(" wide //weight: 1
        $x_1_4 = "foreach" wide //weight: 1
        $x_1_5 = "http" wide //weight: 1
        $x_1_6 = "new-object" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_AL_2147937007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AL!MTB"
        threat_id = "2147937007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wscript.shell" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "mshta" wide //weight: 10
        $x_10_4 = "vbscript:Execute(" wide //weight: 10
        $x_10_5 = "start-process" wide //weight: 10
        $x_1_6 = " irm" wide //weight: 1
        $x_1_7 = "invoke-webrequest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZD_2147937008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZD!MTB"
        threat_id = "2147937008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = ".shop/" wide //weight: 50
        $x_50_2 = ".xyz/" wide //weight: 50
        $x_50_3 = ".icu/" wide //weight: 50
        $x_50_4 = ".lat/" wide //weight: 50
        $x_50_5 = ".fun/" wide //weight: 50
        $x_50_6 = ".bet/" wide //weight: 50
        $x_50_7 = ".info/" wide //weight: 50
        $x_50_8 = ".live/" wide //weight: 50
        $x_50_9 = ".life/" wide //weight: 50
        $x_50_10 = ".online/" wide //weight: 50
        $x_50_11 = ".bond/" wide //weight: 50
        $x_50_12 = ".top/" wide //weight: 50
        $x_50_13 = ".world/" wide //weight: 50
        $x_50_14 = ".forest/" wide //weight: 50
        $x_50_15 = ".today/" wide //weight: 50
        $x_50_16 = ".run/" wide //weight: 50
        $x_50_17 = ".sbs/" wide //weight: 50
        $x_50_18 = ".mom/" wide //weight: 50
        $x_50_19 = ".digital/" wide //weight: 50
        $x_50_20 = ".hair/" wide //weight: 50
        $x_50_21 = ".click/" wide //weight: 50
        $x_50_22 = ".cyou/" wide //weight: 50
        $x_50_23 = ".beauty/" wide //weight: 50
        $x_1_24 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_25 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_26 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_27 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 1, accuracy: High
        $x_1_28 = {48 00 75 00 6d 00 30 04 6e 00 [0-30] 21 04 41 00 50 00 54 00 43 00 48 00 41 00}  //weight: 1, accuracy: Low
        $x_1_29 = "CIoudfIare Unique One-time" ascii //weight: 1
        $x_1_30 = "captcha" wide //weight: 1
        $x_1_31 = "Press Enter" wide //weight: 1
        $x_1_32 = "robot" wide //weight: 1
        $x_1_33 = "human" wide //weight: 1
        $x_1_34 = " ray" wide //weight: 1
        $x_1_35 = "verif" wide //weight: 1
        $x_1_36 = " recaptcha" wide //weight: 1
        $x_1_37 = " re captcha" wide //weight: 1
        $x_1_38 = " rCAPTCHA" wide //weight: 1
        $x_1_39 = " clip FREE" wide //weight: 1
        $x_1_40 = " Over FREE" wide //weight: 1
        $x_1_41 = "robot: r" wide //weight: 1
        $x_1_42 = "robot - r" wide //weight: 1
        $x_1_43 = "Cloudflare" wide //weight: 1
        $x_1_44 = "- Over FREE" wide //weight: 1
        $x_1_45 = "Google Meet" wide //weight: 1
        $x_1_46 = "DNS service" wide //weight: 1
        $x_1_47 = "robot - Cloudflare" wide //weight: 1
        $x_1_48 = "robot: Cloudflare" wide //weight: 1
        $x_1_49 = "robot: CAPTCHA" wide //weight: 1
        $x_1_50 = "robot - CAPTCHA" wide //weight: 1
        $x_1_51 = "Human - r" wide //weight: 1
        $x_1_52 = "Human: r" wide //weight: 1
        $x_1_53 = "Human: CAPTCHA" wide //weight: 1
        $x_1_54 = "Human - CAPTCHA" wide //weight: 1
        $x_1_55 = "Guard: Answer" wide //weight: 1
        $x_1_56 = "Microsoft Windows: Fix Internet DNS Service reconnect" wide //weight: 1
        $x_1_57 = "Restart DNS service in the Microsoft Windows system" wide //weight: 1
        $x_1_58 = "netstatuscheck" wide //weight: 1
        $n_5000_59 = "msedgewebview2.exe" wide //weight: -5000
        $n_1000_60 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_GVA_2147937010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GVA!MTB"
        threat_id = "2147937010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "powershell" wide //weight: 5
        $x_5_2 = {69 00 72 00 6d 00 20 00 [0-255] 3a 00 [0-10] 2f 00 24 00}  //weight: 5, accuracy: Low
        $x_3_3 = "iex" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZC_2147937321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZC!MTB"
        threat_id = "2147937321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "115"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_5_2 = "http" wide //weight: 5
        $x_5_3 = " iex" wide //weight: 5
        $x_5_4 = "iwr" wide //weight: 5
        $x_5_5 = "irm" wide //weight: 5
        $x_5_6 = "invoke-expression" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZC_2147937321_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZC!MTB"
        threat_id = "2147937321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".replace('#','')" wide //weight: 1
        $x_1_2 = ".replace('@','')" wide //weight: 1
        $x_10_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-1] 30 00 2d 00 77 00 [0-5] 68 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_SH_2147937478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SH"
        threat_id = "2147937478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "113"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "-w hidden" wide //weight: 10
        $x_10_3 = "-w 1" wide //weight: 10
        $x_10_4 = "-w h " wide //weight: 10
        $x_1_5 = "::frombase64string(" wide //weight: 1
        $x_1_6 = "-useb " wide //weight: 1
        $x_1_7 = {2d 00 75 00 72 00 69 00 90 00 02 00 10 00 2d 00 75 00 73 00 65 00 62 00 61 00 73 00 69 00 63 00 70 00 61 00 72 00 73 00 69 00 6e 00 67 00 3b 00}  //weight: 1, accuracy: High
        $x_1_8 = "iwr" wide //weight: 1
        $x_1_9 = "iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DAE_2147937503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAE!MTB"
        threat_id = "2147937503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "116"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = {73 00 74 00 61 00 72 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-15] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_5_3 = "-outfile" wide //weight: 5
        $x_1_4 = "iex" wide //weight: 1
        $x_1_5 = "invoke-expression" wide //weight: 1
        $x_1_6 = "invoke-webrequest" wide //weight: 1
        $x_1_7 = "iwr" wide //weight: 1
        $x_1_8 = "irm" wide //weight: 1
        $x_1_9 = "invoke-restmethod" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DAF_2147937504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAF!MTB"
        threat_id = "2147937504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "131"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "iex" wide //weight: 10
        $x_10_4 = "iwr" wide //weight: 10
        $x_1_5 = "I confirm that I am human reCAPTCHA" wide //weight: 1
        $x_1_6 = "Paste it For Passing" wide //weight: 1
        $x_1_7 = "I am not a robot | Captcha" wide //weight: 1
        $x_1_8 = "I am not a robot - V" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DAJ_2147937505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAJ!MTB"
        threat_id = "2147937505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "116"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = {73 00 74 00 61 00 72 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-15] 2d 00 6e 00 6f 00 6e 00 65 00 77 00 77 00 69 00 6e 00 64 00 6f 00 77 00}  //weight: 10, accuracy: Low
        $x_5_3 = "-outfile" wide //weight: 5
        $x_1_4 = "iex" wide //weight: 1
        $x_1_5 = "invoke-expression" wide //weight: 1
        $x_1_6 = "invoke-webrequest" wide //weight: 1
        $x_1_7 = "iwr" wide //weight: 1
        $x_1_8 = "irm" wide //weight: 1
        $x_1_9 = "invoke-restmethod" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_YE_2147937536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.YE!MTB"
        threat_id = "2147937536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 00 73 00 68 00 74 00 61 00 [0-255] 2e 00 6d 00 70 00 33 00}  //weight: 10, accuracy: Low
        $x_10_2 = {6d 00 73 00 68 00 74 00 61 00 [0-255] 2e 00 6d 00 70 00 34 00}  //weight: 10, accuracy: Low
        $x_10_3 = {6d 00 73 00 68 00 74 00 61 00 [0-255] 2e 00 78 00 6c 00 6c 00}  //weight: 10, accuracy: Low
        $x_10_4 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 74 70 00 73 00 3a 00 2f 00 2f 00 61 00 6e 00 61 00 61 00 6d 00 77 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-6] 2e 00 70 00 68 00 70 00 5c 00 31 00}  //weight: 10, accuracy: Low
        $x_10_5 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 74 70 00 73 00 3a 00 2f 00 2f 00 72 00 65 00 61 00 2e 00 67 00 72 00 75 00 70 00 6f 00 6c 00 61 00 6c 00 65 00 67 00 69 00 6f 00 6e 00 2e 00 65 00 63 00 2f 00 [0-6] 2e 00 70 00 68 00 70 00 5c 00 31 00}  //weight: 10, accuracy: Low
        $x_10_6 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 74 70 00 73 00 3a 00 2f 00 2f 00 67 00 72 00 65 00 65 00 6e 00 69 00 6e 00 64 00 75 00 73 00 74 00 72 00 79 00 2e 00 70 00 6c 00 2f 00 [0-6] 2e 00 70 00 68 00 70 00 5c 00 31 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_DAI_2147937671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAI!MTB"
        threat_id = "2147937671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "powershell" wide //weight: 50
        $x_1_2 = "-UseBasicParsing).Content" wide //weight: 1
        $x_1_3 = "iex" wide //weight: 1
        $x_1_4 = "iwr $" wide //weight: 1
        $x_1_5 = "verif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_HA_2147937679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.HA!MTB"
        threat_id = "2147937679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 27 00 [0-2] 27 00 2c 00 27 00 27 00 29 00}  //weight: 10, accuracy: Low
        $x_1_2 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_SDA_2147937775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SDA"
        threat_id = "2147937775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = " iex" wide //weight: 10
        $x_10_4 = "iwr" wide //weight: 10
        $x_10_5 = "irm" wide //weight: 10
        $x_10_6 = "invoke-expression" wide //weight: 10
        $n_500_7 = "msiexec.exe" wide //weight: -500
        $n_500_8 = ".ps1" wide //weight: -500
        $n_500_9 = ".hta" wide //weight: -500
        $n_500_10 = "dml.bpweb.bp.com" wide //weight: -500
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_SJ_2147937800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SJ"
        threat_id = "2147937800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-split" wide //weight: 1
        $x_1_2 = "-join" wide //weight: 1
        $x_1_3 = "substring" wide //weight: 1
        $x_1_4 = "where-object {$_}" wide //weight: 1
        $x_1_5 = "foreach-object {[char]([convert]::toint32($_,16))}" wide //weight: 1
        $x_3_6 = "'(?<=\\g..)'|%{[char]([convert]::toint32($_,16))})" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_SZZ_2147937801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SZZ"
        threat_id = "2147937801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "(([char](105))+([char](101))+([char](120)))" wide //weight: 1
        $x_1_3 = "(([char](83))+([char](116))+([char](97))+([char](114))+([char](116))+" wide //weight: 1
        $x_1_4 = "([char](45))+([char](80))+([char](114))+([char](111))+([char](99))+([char](101))+([char](115))+([char](115))+([char](32))" wide //weight: 1
        $x_1_5 = "([char](34))+([char](36))+([char](101))+([char](110))+([char](118))+([char](58))" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_TFA_2147938012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.TFA"
        threat_id = "2147938012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_1_3 = "Capcha" wide //weight: 1
        $x_1_4 = "Your ID" wide //weight: 1
        $x_1_5 = "confirm" wide //weight: 1
        $x_1_6 = "human" wide //weight: 1
        $n_1000_7 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_8 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_TFC_2147938013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.TFC"
        threat_id = "2147938013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_1_2 = "FromBase64String" wide //weight: 1
        $x_1_3 = "-bxor" wide //weight: 1
        $x_1_4 = "iex(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_STA_2147938015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STA"
        threat_id = "2147938015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 10, accuracy: High
        $x_2_2 = {64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 63 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 28 00 [0-2] 63 00 6f 00 70 00 79 00 [0-2] 29 00}  //weight: 2, accuracy: Low
        $x_2_3 = {64 6f 63 75 6d 65 6e 74 2e 65 78 65 63 43 6f 6d 6d 61 6e 64 28 [0-2] 63 6f 70 79 [0-2] 29}  //weight: 2, accuracy: Low
        $x_1_4 = {64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 63 00 72 00 65 00 61 00 74 00 65 00 45 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 28 00 [0-2] 74 00 65 00 78 00 74 00 61 00 72 00 65 00 61 00 [0-2] 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {64 6f 63 75 6d 65 6e 74 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 [0-2] 74 65 78 74 61 72 65 61 [0-2] 29}  //weight: 1, accuracy: Low
        $x_1_6 = {64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 62 00 6f 00 64 00 79 00 2e 00 61 00 70 00 70 00 65 00 6e 00 64 00 [0-48] 2e 00 73 00 65 00 6c 00 65 00 63 00 74 00 28 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {64 6f 63 75 6d 65 6e 74 2e 62 6f 64 79 2e 61 70 70 65 6e 64 [0-48] 2e 73 65 6c 65 63 74 28 29}  //weight: 1, accuracy: Low
        $x_1_8 = "captcha" ascii //weight: 1
        $x_1_9 = "verification-id" ascii //weight: 1
        $x_1_10 = {79 00 6f 00 75 00 20 00 61 00 72 00 65 00 [0-6] 68 00 75 00 6d 00 61 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_11 = {79 6f 75 20 61 72 65 [0-6] 68 75 6d 61 6e}  //weight: 1, accuracy: Low
        $x_1_12 = {2e 00 61 00 64 00 64 00 45 00 76 00 65 00 6e 00 74 00 4c 00 69 00 73 00 74 00 65 00 6e 00 65 00 72 00 28 00 [0-2] 63 00 6c 00 69 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_13 = {2e 61 64 64 45 76 65 6e 74 4c 69 73 74 65 6e 65 72 28 [0-2] 63 6c 69 63 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_TFB_2147938017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.TFB"
        threat_id = "2147938017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "JABkAG8AdwBuAGwAbwBhAGQAVQByAGwAIAA9ACAAIgBoAHQAdABwAHMAOgAvAC8AcwBlAGMAdQByAGkAdAB5AC4AYwBsAG8AdQBkAHMAdAB3AHIALgBjAG8AbQAvAE" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_STB_2147938198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STB"
        threat_id = "2147938198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = " # " wide //weight: 1
        $x_1_3 = "://" wide //weight: 1
        $x_1_4 = ".ogg #" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_STB_2147938198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STB"
        threat_id = "2147938198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "301"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mshta" wide //weight: 100
        $x_100_2 = " # " wide //weight: 100
        $x_100_3 = "://" wide //weight: 100
        $x_1_4 = "confirm" wide //weight: 1
        $x_1_5 = "captcha" wide //weight: 1
        $x_1_6 = "human" wide //weight: 1
        $x_1_7 = "robot" wide //weight: 1
        $x_1_8 = "verif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DAO_2147938209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAO!MTB"
        threat_id = "2147938209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_5_2 = "-UseBasicParsing).Content" wide //weight: 5
        $x_1_3 = "iex" wide //weight: 1
        $x_1_4 = "iwr" wide //weight: 1
        $x_1_5 = "$_ -bxor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DAR_2147938210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAR!MTB"
        threat_id = "2147938210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mshta" wide //weight: 100
        $x_1_2 = "CIoudfIare Unique One-time" wide //weight: 1
        $x_1_3 = "User Ref: Alpha" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DAS_2147938211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAS!MTB"
        threat_id = "2147938211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mshta" wide //weight: 100
        $x_1_2 = {20 00 49 00 09 20}  //weight: 1, accuracy: High
        $x_1_3 = {09 20 49 00 09 20}  //weight: 1, accuracy: High
        $x_1_4 = {09 20 49 00 20 00}  //weight: 1, accuracy: High
        $x_1_5 = {20 00 99 03 20 00}  //weight: 1, accuracy: High
        $x_1_6 = {09 20 99 03 09 20}  //weight: 1, accuracy: High
        $x_1_7 = {20 00 99 03 09 20}  //weight: 1, accuracy: High
        $x_1_8 = {20 00 72 00 3e 04}  //weight: 1, accuracy: High
        $x_1_9 = {20 00 7e 02 80 05}  //weight: 1, accuracy: High
        $x_1_10 = {20 00 52 00 bf 03}  //weight: 1, accuracy: High
        $x_1_11 = {02 00 43 00 91 03}  //weight: 1, accuracy: High
        $x_1_12 = {02 00 21 04 91 03}  //weight: 1, accuracy: High
        $x_1_13 = {02 00 21 04 41 00}  //weight: 1, accuracy: High
        $x_1_14 = {09 20 43 00 91 03}  //weight: 1, accuracy: High
        $x_1_15 = {09 20 21 04 91 03}  //weight: 1, accuracy: High
        $x_1_16 = {09 20 21 04 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_TFD_2147938308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.TFD"
        threat_id = "2147938308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = "Verification" wide //weight: 1
        $x_1_4 = "|iex" wide //weight: 1
        $x_1_5 = " iwr " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DAT_2147938309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAT!MTB"
        threat_id = "2147938309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "202"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_100_2 = " # " wide //weight: 100
        $x_1_3 = "iwr" wide //weight: 1
        $x_1_4 = "|iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DAU_2147938314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAU!MTB"
        threat_id = "2147938314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_1_2 = "-UseBasicParsing).Content" wide //weight: 1
        $x_1_3 = "iex" wide //weight: 1
        $x_1_4 = "iwr" wide //weight: 1
        $x_5_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-9] 2e 00 [0-9] 2e 00 [0-9] 2e 00 [0-9] 3a 00 [0-9] 2f 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_STC_2147938321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STC"
        threat_id = "2147938321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 [0-16] 20 00 2d 00 77 00 20 00 68 00 20 00 2d 00 63 00 20 00 [0-4] 69 00 65 00 78 00 20 00 24 00 28 00 69 00 72 00 6d 00}  //weight: 100, accuracy: Low
        $x_2_2 = ":8080/$($z" wide //weight: 2
        $x_1_3 = "('01/01/' + '1970')" wide //weight: 1
        $x_1_4 = "$x = ($z - $y).TotalSeconds" wide //weight: 1
        $x_1_5 = "::Floor($x); $v = $w - ($w % 16)" wide //weight: 1
        $x_1_6 = {3a 00 3a 00 55 00 74 00 63 00 4e 00 6f 00 77 00 3b 00 20 00 24 00 79 00 20 00 3d 00 20 00 [0-4] 64 00 61 00 74 00 65 00 74 00 69 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = "[int64]$v))" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_STD_2147938322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STD"
        threat_id = "2147938322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 [0-16] 20 00 2d 00 77 00 20 00 68 00 20 00 2d 00 63 00 20 00 [0-4] 69 00 65 00 78 00 20 00 24 00 28 00 69 00 72 00 6d 00}  //weight: 100, accuracy: Low
        $x_1_2 = "MQA5ADcAMAA=" wide //weight: 1
        $x_1_3 = "MAAxAC8AMAAxAC8A" wide //weight: 1
        $x_1_4 = "(datetime($(Text.Encoding::Unicode.GetString(Convert::FromBase64String" wide //weight: 1
        $x_1_5 = "math::Floor(${__/==\\_/\\___/===\\})" wide //weight: 1
        $x_1_6 = "int64${___/==\\/=\\/\\__/==}))" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_SF_2147938437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SF"
        threat_id = "2147938437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-255] 20 00 2d 00 77 00 [0-32] 20 00 31 00}  //weight: 10, accuracy: Low
        $x_10_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-255] 20 00 2d 00 77 00 [0-32] 20 00 68 00}  //weight: 10, accuracy: Low
        $x_1_3 = "http" wide //weight: 1
        $n_100_4 = "trackmap.epic.com" wide //weight: -100
        $n_100_5 = ".hta" wide //weight: -100
        $n_100_6 = ".ps1" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZA_2147938438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZA"
        threat_id = "2147938438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-w" wide //weight: 1
        $x_1_3 = "http" wide //weight: 1
        $n_100_4 = ".ps1" wide //weight: -100
        $n_100_5 = ".hta" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZB_2147938439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZB"
        threat_id = "2147938439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "-w" wide //weight: 10
        $x_1_3 = "http" wide //weight: 1
        $x_1_4 = "iex" wide //weight: 1
        $x_1_5 = "iwr" wide //weight: 1
        $n_300_6 = ".ps1" wide //weight: -300
        $n_300_7 = ".hta" wide //weight: -300
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_STX_2147938567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STX"
        threat_id = "2147938567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = " # " wide //weight: 1
        $x_1_3 = "://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DAW_2147938589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAW!MTB"
        threat_id = "2147938589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell $" wide //weight: 100
        $x_100_2 = "powershell -Command $" wide //weight: 100
        $x_10_3 = "-UseBasicParsing" wide //weight: 10
        $x_10_4 = ".Content" wide //weight: 10
        $x_1_5 = "Invoke-WebRequest" wide //weight: 1
        $x_1_6 = "iwr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_SI_2147939078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SI"
        threat_id = "2147939078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6d 00 64 00 [0-16] 2f 00 63 00}  //weight: 10, accuracy: Low
        $x_10_2 = "/min" wide //weight: 10
        $x_10_3 = "start " wide //weight: 10
        $x_10_4 = "powershell " wide //weight: 10
        $x_10_5 = "http" wide //weight: 10
        $n_100_6 = ".ps1" wide //weight: -100
        $n_100_7 = ".hta" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_STY_2147939083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STY"
        threat_id = "2147939083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 63 00 75 00 72 00 6c 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = ".txt | iex'#" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_STZ_2147939084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STZ"
        threat_id = "2147939084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 63 00 75 00 72 00 6c 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_2 = "| iex" wide //weight: 10
        $x_1_3 = "piverif.txt" wide //weight: 1
        $x_1_4 = "patoss.txt" wide //weight: 1
        $x_1_5 = "zipzig.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZE_2147939086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZE"
        threat_id = "2147939086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_10_2 = {68 00 74 00 74 00 70 00 90 00 02 00 ff 00 2e 00 6f 00 67 00 67 00}  //weight: 10, accuracy: High
        $x_10_3 = {20 00 05 27 20 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZE_2147939086_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZE"
        threat_id = "2147939086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1150"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "mshta" wide //weight: 50
        $x_50_2 = "http" wide //weight: 50
        $x_50_3 = "2no.co" wide //weight: 50
        $x_1000_4 = "=+=" wide //weight: 1000
        $x_1000_5 = "+=+" wide //weight: 1000
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 3 of ($x_50_*))) or
            ((2 of ($x_1000_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZF_2147939088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZF"
        threat_id = "2147939088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZF_2147939088_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZF"
        threat_id = "2147939088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "-w" wide //weight: 2
        $x_2_3 = "http" wide //weight: 2
        $x_2_4 = "curl" wide //weight: 2
        $n_5000_5 = ".ps1" wide //weight: -5000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_RXH_2147939166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.RXH!MTB"
        threat_id = "2147939166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_5_2 = ").Downlo'" wide //weight: 5
        $x_2_3 = "http" wide //weight: 2
        $x_1_4 = "-Join" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZG_2147939200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZG"
        threat_id = "2147939200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = "start" wide //weight: 1
        $x_1_4 = "iex((iwr" wide //weight: 1
        $x_1_5 = "-UseBasicParsing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZG_2147939200_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZG"
        threat_id = "2147939200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "400"
        strings_accuracy = "Low"
    strings:
        $x_200_1 = "powershell" wide //weight: 200
        $x_200_2 = "-w" wide //weight: 200
        $x_400_3 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-255] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_4 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 [0-255] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_5 = {63 00 6d 00 64 00 [0-48] 63 00 75 00 72 00 6c 00 [0-48] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_6 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-48] 63 00 75 00 72 00 6c 00 [0-48] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $n_500_7 = ".ps1" wide //weight: -500
        $n_500_8 = ".hta" wide //weight: -500
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_200_*))) or
            ((1 of ($x_400_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DBC_2147939201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBC!MTB"
        threat_id = "2147939201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "mshta" wide //weight: 1
        $x_10_3 = "irs.gov-" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_YG_2147939281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.YG!MTB"
        threat_id = "2147939281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "iex(irm($" wide //weight: 10
        $x_10_3 = ".ToString()" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_STW_2147939301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STW"
        threat_id = "2147939301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "202"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mshta" wide //weight: 100
        $x_100_2 = ":\\" wide //weight: 100
        $x_1_3 = "rem" wide //weight: 1
        $x_1_4 = "confirm" wide //weight: 1
        $x_1_5 = "identity" wide //weight: 1
        $x_1_6 = "verification" wide //weight: 1
        $x_1_7 = "not a robot" wide //weight: 1
        $x_1_8 = {d1 00 81 00 d0 00 b0 00 d1 00 80 00 74 00 63 00 68 00 61 00}  //weight: 1, accuracy: High
        $x_1_9 = "human" wide //weight: 1
        $x_1_10 = "id:" wide //weight: 1
        $x_1_11 = "authorized" wide //weight: 1
        $x_1_12 = "gatesig:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DAY_2147939302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAY!MTB"
        threat_id = "2147939302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_1_2 = "-enc" wide //weight: 1
        $x_1_3 = ".DownloadString(" wide //weight: 1
        $x_1_4 = "New-Object Net.WebClient" wide //weight: 1
        $x_1_5 = "|iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DBB_2147939303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBB!MTB"
        threat_id = "2147939303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mshta" wide //weight: 100
        $x_10_2 = "vbscript:" wide //weight: 10
        $x_10_3 = "CreateObject(" wide //weight: 10
        $x_10_4 = "wIndOw.cLoSe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_HC_2147939325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.HC!MTB"
        threat_id = "2147939325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_25_1 = "(iwr http" wide //weight: 25
        $x_25_2 = "iex" wide //weight: 25
        $x_10_3 = "-useb)" wide //weight: 10
        $x_5_4 = "powershell" wide //weight: 5
        $x_55_5 = "dqakagkazqb4acgaaqb3ahiaiaboahqadabwah" wide //weight: 55
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_25_*) and 1 of ($x_10_*))) or
            ((1 of ($x_55_*) and 1 of ($x_5_*))) or
            ((1 of ($x_55_*) and 1 of ($x_10_*))) or
            ((1 of ($x_55_*) and 1 of ($x_25_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_HD_2147939326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.HD!MTB"
        threat_id = "2147939326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_10_2 = "http" wide //weight: 10
        $n_10_3 = ".hta" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_GVC_2147939392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GVC!MTB"
        threat_id = "2147939392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "start-process" wide //weight: 2
        $x_2_3 = "runas" wide //weight: 2
        $x_2_4 = "http" wide //weight: 2
        $x_2_5 = "download" wide //weight: 2
        $x_1_6 = "new-object" wide //weight: 1
        $x_1_7 = "net.webclient" wide //weight: 1
        $x_1_8 = ".invoke" wide //weight: 1
        $x_1_9 = "scriptblock" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_STV_2147939395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STV"
        threat_id = "2147939395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "not a robot" wide //weight: 100
        $x_1_2 = "curl" wide //weight: 1
        $x_1_3 = "verif" wide //weight: 1
        $x_1_4 = "confirm" wide //weight: 1
        $x_1_5 = "press" wide //weight: 1
        $x_1_6 = "captcha" wide //weight: 1
        $x_1_7 = "cloudflare" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DAZ_2147939396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAZ!MTB"
        threat_id = "2147939396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "171"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mshta" wide //weight: 100
        $x_50_2 = "gclid=" wide //weight: 50
        $x_20_3 = ".wav?" wide //weight: 20
        $x_20_4 = ".opus?" wide //weight: 20
        $x_1_5 = ".shop/" wide //weight: 1
        $x_1_6 = ".online/" wide //weight: 1
        $n_1000_7 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_8 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_STU_2147939755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STU"
        threat_id = "2147939755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|iex" wide //weight: 1
        $x_1_2 = "curl" wide //weight: 1
        $n_1000_3 = "http" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_STU_2147939755_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STU"
        threat_id = "2147939755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-32] 63 00 75 00 72 00 6c 00 [0-64] 2f 00 70 00 73 00 7c 00 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-32] 63 00 75 00 72 00 6c 00 [0-64] 2f 00 74 00 78 00 74 00 7c 00 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-32] 63 00 75 00 72 00 6c 00 [0-64] 2f 00 6c 00 6f 00 67 00 7c 00 69 00 65 00 78 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_SAA_2147939763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SAA"
        threat_id = "2147939763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_10_2 = {20 00 05 27 20 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_AB_2147940112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AB"
        threat_id = "2147940112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iplogger.co" wide //weight: 1
        $x_1_2 = "whim-proof.beauty" wide //weight: 1
        $x_1_3 = "stag-cnd-files.oss-ap-southeast-1.aliyuncs.com" wide //weight: 1
        $x_1_4 = "helperection.top" wide //weight: 1
        $x_1_5 = "abodeshop.shop" wide //weight: 1
        $x_1_6 = "dybep.fun" wide //weight: 1
        $x_1_7 = "esyn.live" wide //weight: 1
        $x_1_8 = "fvlc.live/" wide //weight: 1
        $x_1_9 = "lwhkr.press/" wide //weight: 1
        $x_1_10 = "thob.live/" wide //weight: 1
        $x_1_11 = "handprintscariness.ru/" ascii //weight: 1
        $x_1_12 = "e.overallwobbly.ru/" wide //weight: 1
        $x_1_13 = "levciavia.top/" wide //weight: 1
        $x_1_14 = "discountly.pw/" wide //weight: 1
        $x_1_15 = "session-cache-zx482.oss-ap-southeast-1.aliyuncs.com/" wide //weight: 1
        $x_1_16 = "yourcialsupply.top/" wide //weight: 1
        $x_1_17 = "ybfl.live/" wide //weight: 1
        $x_1_18 = "jasonstatham.pw/" wide //weight: 1
        $x_1_19 = "tomhanks.pw/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_YHH_2147940376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.YHH!MTB"
        threat_id = "2147940376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = {3d d8 e9 df}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZH_2147940389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZH"
        threat_id = "2147940389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "mshta" wide //weight: 2
        $x_5_3 = "http" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_SEZ_2147940391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SEZ"
        threat_id = "2147940391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 61 00 63 00 74 00 69 00 76 00 69 00 74 00 79 00 64 00 6d 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_2 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 62 00 65 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_3 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 62 00 69 00 7a 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_4 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 62 00 6c 00 6f 00 67 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_5 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 62 00 6f 00 6e 00 64 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_6 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 62 00 75 00 7a 00 7a 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_7 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 61 00 6d 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_8 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 64 00 61 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_9 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 6c 00 69 00 63 00 6b 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_10 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 6c 00 75 00 62 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_11 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_12 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 75 00 6c 00 74 00 75 00 72 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_13 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 79 00 6f 00 75 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_14 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 61 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_15 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 69 00 67 00 69 00 74 00 61 00 6c 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_16 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_17 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 65 00 6d 00 70 00 6c 00 6f 00 79 00 65 00 72 00 64 00 62 00 7a 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_18 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 65 00 70 00 73 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_19 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 6f 00 72 00 65 00 73 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_20 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 6c 00 76 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_21 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 75 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_22 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 67 00 64 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_23 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 68 00 61 00 69 00 72 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_24 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 68 00 65 00 6c 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_25 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 69 00 63 00 75 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_26 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 69 00 6e 00 66 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_27 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 61 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_28 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 66 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_29 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 6e 00 6b 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_30 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 6f 00 61 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_31 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 76 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_32 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 34 00 61 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_33 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 64 00 62 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_34 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_35 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 70 00 33 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_36 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 70 00 34 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_37 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_38 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_39 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6f 00 72 00 67 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_40 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 61 00 72 00 74 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_41 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 72 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_42 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 77 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_43 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 61 00 63 00 69 00 6e 00 67 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_44 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_45 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 69 00 73 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_46 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 76 00 69 00 65 00 77 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_47 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 75 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_48 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 62 00 73 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_49 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_50 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 63 00 69 00 65 00 6e 00 63 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_51 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 68 00 6f 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_52 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 69 00 74 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_53 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 70 00 61 00 63 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_54 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 6f 00 72 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_55 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 72 00 65 00 61 00 6d 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_56 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 75 00 64 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_57 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 63 00 68 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_58 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_59 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 72 00 72 00 69 00 66 00 79 00 65 00 6e 00 79 00 62 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_60 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 6f 00 64 00 61 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_61 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 6f 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_62 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 76 00 69 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_63 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 77 00 6f 00 72 00 6b 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_64 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 77 00 6f 00 72 00 6c 00 64 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_65 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 78 00 6c 00 6c 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_66 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 78 00 79 00 7a 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_67 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 79 00 6f 00 6b 00 6f 00 68 00 61 00 6d 00 61 00 2f 00}  //weight: 10, accuracy: Low
        $n_500_68 = ".ps1" wide //weight: -500
        $n_500_69 = ".hta" wide //weight: -500
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_SG_2147940467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SG"
        threat_id = "2147940467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta.exe" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $n_100_3 = ".hta" wide //weight: -100
        $n_100_4 = ".html" wide //weight: -100
        $n_100_5 = ".htm" wide //weight: -100
        $n_100_6 = ".ps1" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ABA_2147940468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ABA"
        threat_id = "2147940468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chatcdn" wide //weight: 1
        $x_1_2 = "duckdns" wide //weight: 1
        $x_1_3 = "digikex.com" wide //weight: 1
        $x_1_4 = "bodlsan.com" wide //weight: 1
        $x_1_5 = ".r2.dev" wide //weight: 1
        $x_1_6 = ".trycloudflare.com" wide //weight: 1
        $x_1_7 = "cloudflare" wide //weight: 1
        $x_1_8 = "pastebin" wide //weight: 1
        $x_1_9 = "pastes.io" wide //weight: 1
        $x_1_10 = "cutt.ly" wide //weight: 1
        $x_1_11 = "tinyurl.com" wide //weight: 1
        $x_1_12 = "rentry.co" wide //weight: 1
        $x_1_13 = "blogspot.com" wide //weight: 1
        $x_1_14 = "bit.ly" wide //weight: 1
        $x_1_15 = "psee.io" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_DAC_2147940469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAC!MTB"
        threat_id = "2147940469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_100_2 = ".shop/" wide //weight: 100
        $x_100_3 = ".xyz/" wide //weight: 100
        $x_100_4 = ".icu/" wide //weight: 100
        $x_100_5 = ".lat/" wide //weight: 100
        $x_100_6 = ".fun/" wide //weight: 100
        $x_100_7 = ".bet/" wide //weight: 100
        $x_100_8 = ".live/" wide //weight: 100
        $x_100_9 = ".life/" wide //weight: 100
        $x_100_10 = ".online/" wide //weight: 100
        $x_100_11 = ".bond/" wide //weight: 100
        $x_100_12 = ".top/" wide //weight: 100
        $x_100_13 = ".world/" wide //weight: 100
        $x_100_14 = ".click/" wide //weight: 100
        $x_100_15 = ".forest/" wide //weight: 100
        $x_100_16 = ".run/" wide //weight: 100
        $x_100_17 = ".was/" wide //weight: 100
        $x_100_18 = ".today/" wide //weight: 100
        $x_100_19 = ".cyou/" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DBL_2147940607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBL!MTB"
        threat_id = "2147940607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "-UseBasicParsing" wide //weight: 10
        $x_10_3 = "[ScRiPtBlOcK]::CrEaTe($" wide //weight: 10
        $x_1_4 = "-W h -C" wide //weight: 1
        $x_1_5 = "-WindowStyle hidden -Command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DBM_2147940752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBM!MTB"
        threat_id = "2147940752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-7] 2d 00 77 00 20 00 68 00}  //weight: 100, accuracy: Low
        $x_100_2 = ") | powershell" wide //weight: 100
        $x_1_3 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DBN_2147940753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBN!MTB"
        threat_id = "2147940753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "131"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mshta" wide //weight: 100
        $x_10_2 = "SHELLEXECUTE" wide //weight: 10
        $x_10_3 = "DeleteFile" wide //weight: 10
        $x_10_4 = "javascript:var" wide //weight: 10
        $x_1_5 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_STT_2147940919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.STT"
        threat_id = "2147940919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " # " wide //weight: 1
        $x_1_2 = "://" wide //weight: 1
        $x_1_3 = "'+'" wide //weight: 1
        $x_1_4 = "]::" wide //weight: 1
        $x_1_5 = ";&$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_ClickFix_AAA_2147940949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AAA"
        threat_id = "2147940949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = {13 20 65 00 4e 00 63 00 6f}  //weight: 1, accuracy: High
        $x_1_3 = "uwb0ageacgb0ac0auabyag8aywblahmacwagaciaaab0ahqacaa6a" wide //weight: 1
        $x_1_4 = "guazaa9ahqacgb1aguaigagaa==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZFA_2147940950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZFA"
        threat_id = "2147940950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "-w" wide //weight: 2
        $x_2_3 = "curl" wide //weight: 2
        $n_5000_4 = ".ps1" wide //weight: -5000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZFB_2147940951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZFB"
        threat_id = "2147940951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "-w" wide //weight: 2
        $x_2_3 = "curl" wide //weight: 2
        $x_2_4 = "|iex" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZI_2147940953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZI"
        threat_id = "2147940953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "replace" wide //weight: 10
        $x_1_2 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_SQ_2147941103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SQ"
        threat_id = "2147941103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "windowsinstaller.installer" wide //weight: 1
        $x_1_3 = "uilevel=2" wide //weight: 1
        $x_1_4 = "installproduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DBO_2147941223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBO!MTB"
        threat_id = "2147941223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "120"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "[ScRiPtBlOcK]::CrEaTe(" wide //weight: 10
        $x_10_3 = "[array]::Reverse($" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DBQ_2147941224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBQ!MTB"
        threat_id = "2147941224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "-UseBasicParsing" wide //weight: 10
        $x_10_3 = "-join" wide //weight: 10
        $x_10_4 = ".Length]" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

