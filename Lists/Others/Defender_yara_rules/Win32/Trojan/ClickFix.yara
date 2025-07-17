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
        $n_100_8 = "msedgewebview2.exe" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
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
        $n_100_24 = "enter to hibernate" wide //weight: -100
        $n_100_25 = "trycloudflare.com" wide //weight: -100
        $n_100_26 = "my.sharepoint.com" wide //weight: -100
        $n_100_27 = "OneDrive" wide //weight: -100
        $n_100_28 = "nike.com" wide //weight: -100
        $n_100_29 = "adminapp" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
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
        $n_100_9 = "msedgewebview2" wide //weight: -100
        $x_100_10 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_11 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_12 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_13 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 100, accuracy: High
        $x_100_14 = {48 00 75 00 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_15 = "CIoudfIare Unique One-time" wide //weight: 100
        $x_100_16 = {21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 100, accuracy: High
        $x_100_17 = {99 03 20 00 61 00 6d 00 20 00 6e 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_18 = {52 00 bf 03 62 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_19 = {60 21 51 02 6d 00 78 05 85 05 74 00}  //weight: 100, accuracy: High
        $x_100_20 = {7e 02 85 05 62 00 85 05 74 00}  //weight: 100, accuracy: High
        $x_100_21 = {f9 03 91 03 a1 03 a4 03 43 00 48 00 41 00}  //weight: 100, accuracy: High
        $x_100_22 = {72 00 0b 20 6f 00 62 00 6f 00 0d 20 74 00}  //weight: 100, accuracy: High
        $x_100_23 = {43 00 41 00 a1 03 54 00 43 00 48 00 41 00}  //weight: 100, accuracy: High
        $x_100_24 = {72 00 6f 00 84 01 6f 00 74 00}  //weight: 100, accuracy: High
        $x_100_25 = {72 00 bf 03 62 00 bf 03 c4 03}  //weight: 100, accuracy: High
        $x_100_26 = {43 00 91 03 50 00 a4 03 43 00 97 03 91 03}  //weight: 100, accuracy: High
        $x_100_27 = {21 04 91 03 20 04 03 a4 21 04 1d 04 91 03}  //weight: 100, accuracy: High
        $x_100_28 = {21 04 91 03 20 04 22 04 21 04 1d 04 41 00}  //weight: 100, accuracy: High
        $x_100_29 = {72 00 3e 04 62 00 3e 04 74 00}  //weight: 100, accuracy: High
        $x_100_30 = {43 00 41 00 50 00 54 00 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_31 = {9d 03 bf 03 6e 00 2d 00 62 00 bf 03 74 00}  //weight: 100, accuracy: High
        $x_100_32 = {68 00 c5 03 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_33 = {35 04 72 00 56 04 66 00 56 04 35 04 64 00}  //weight: 100, accuracy: High
        $x_100_34 = {21 04 6c 00 3e 04 75 00 64 00}  //weight: 100, accuracy: High
        $x_100_35 = {7e 02 80 05 62 00 80 05 1f 1d}  //weight: 100, accuracy: High
        $x_100_36 = {33 04 bf 03 62 00 3e 04 74 00}  //weight: 100, accuracy: High
        $x_100_37 = {1d 04 75 00 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_38 = {21 04 10 04 20 04 22 04 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_39 = {21 04 10 04 50 00 54 00 43 00 97 03 41 00}  //weight: 100, accuracy: High
        $x_100_40 = {1d 04 c5 03 6d 00 30 04 6e 00}  //weight: 100, accuracy: High
        $x_100_41 = {f9 03 91 03 20 04 22 04 21 04 1d 04 91 03}  //weight: 100, accuracy: High
        $n_1000_42 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_43 = "if false == false echo" wide //weight: -1000
        $n_1000_44 = "Cinterion_Snapdragon_X20_LTE" wide //weight: -1000
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
        $n_100_14 = "chocolatey" wide //weight: -100
        $n_100_15 = "zoom" wide //weight: -100
        $n_100_16 = "intune-resources" wide //weight: -100
        $n_100_17 = "start-menu" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
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
        $n_100_7 = "youtube.com" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
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
        $x_50_20 = ".lol/" wide //weight: 50
        $x_50_21 = ".hair/" wide //weight: 50
        $x_50_22 = ".click/" wide //weight: 50
        $x_50_23 = ".cyou/" wide //weight: 50
        $x_50_24 = ".motorcycles/" wide //weight: 50
        $x_50_25 = ".beauty/" wide //weight: 50
        $x_1_26 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_27 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_28 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04}  //weight: 1, accuracy: High
        $x_1_29 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00}  //weight: 1, accuracy: High
        $x_1_30 = {48 00 75 00 6d 00 30 04 6e 00 [0-30] 21 04 41 00 50 00 54 00 43 00 48 00 41 00}  //weight: 1, accuracy: Low
        $x_1_31 = "CIoudfIare Unique One-time" ascii //weight: 1
        $x_1_32 = "captcha" wide //weight: 1
        $x_1_33 = "Press Enter" wide //weight: 1
        $x_1_34 = "robot" wide //weight: 1
        $x_1_35 = "human" wide //weight: 1
        $x_1_36 = " ray" wide //weight: 1
        $x_1_37 = "verif" wide //weight: 1
        $x_1_38 = " recaptcha" wide //weight: 1
        $x_1_39 = " re captcha" wide //weight: 1
        $x_1_40 = " rCAPTCHA" wide //weight: 1
        $x_1_41 = " clip FREE" wide //weight: 1
        $x_1_42 = " Over FREE" wide //weight: 1
        $x_1_43 = "robot: r" wide //weight: 1
        $x_1_44 = "robot - r" wide //weight: 1
        $x_1_45 = "Cloudflare" wide //weight: 1
        $x_1_46 = "- Over FREE" wide //weight: 1
        $x_1_47 = "Google Meet" wide //weight: 1
        $x_1_48 = "DNS service" wide //weight: 1
        $x_1_49 = "robot - Cloudflare" wide //weight: 1
        $x_1_50 = "robot: Cloudflare" wide //weight: 1
        $x_1_51 = "robot: CAPTCHA" wide //weight: 1
        $x_1_52 = "robot - CAPTCHA" wide //weight: 1
        $x_1_53 = "Human - r" wide //weight: 1
        $x_1_54 = "Human: r" wide //weight: 1
        $x_1_55 = "Human: CAPTCHA" wide //weight: 1
        $x_1_56 = "Human - CAPTCHA" wide //weight: 1
        $x_1_57 = "Guard: Answer" wide //weight: 1
        $x_1_58 = "Microsoft Windows: Fix Internet DNS Service reconnect" wide //weight: 1
        $x_1_59 = "Restart DNS service in the Microsoft Windows system" wide //weight: 1
        $x_1_60 = "netstatuscheck" wide //weight: 1
        $x_1_61 = "product call install" wide //weight: 1
        $n_5000_62 = "msedgewebview2.exe" wide //weight: -5000
        $n_1000_63 = "if false == false echo" wide //weight: -1000
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
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "-w hidden" wide //weight: 10
        $x_10_3 = "-w 1" wide //weight: 10
        $x_10_4 = "-w h " wide //weight: 10
        $x_10_5 = {e2 00 80 00 95 00 77 00 20 00 68 00 20 00}  //weight: 10, accuracy: High
        $x_10_6 = {e2 00 80 00 94 00 77 00 20 00 68 00 20 00}  //weight: 10, accuracy: High
        $x_10_7 = {e2 00 80 00 94 00 77 00 20 00 31 00 20 00}  //weight: 10, accuracy: High
        $x_10_8 = {e2 00 80 00 95 00 77 00 20 00 31 00 20 00}  //weight: 10, accuracy: High
        $x_10_9 = "/w h " wide //weight: 10
        $x_10_10 = "/w 1 " wide //weight: 10
        $x_1_11 = "::frombase64string(" wide //weight: 1
        $x_1_12 = "-useb " wide //weight: 1
        $x_1_13 = {2d 00 75 00 72 00 69 00 [0-16] 2d 00 75 00 73 00 65 00 62 00 61 00 73 00 69 00 63 00 70 00 61 00 72 00 73 00 69 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_11_14 = {2e 00 6c 00 65 00 6e 00 67 00 74 00 68 00 [0-16] 2d 00 6a 00 6f 00 69 00 6e 00 [0-48] 3d 00 5b 00 74 00 65 00 78 00 74 00 2e 00 65 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 75 00 74 00 66 00 38 00 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 66 00 72 00 6f 00 6d 00 62 00 61 00 73 00 65 00 36 00 34 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 [0-48] 69 00 65 00 78 00 [0-48] 28 00 69 00 77 00 72 00 20 00 2d 00 75 00 72 00 69 00 20 00 24 00}  //weight: 11, accuracy: Low
        $x_1_15 = "iwr" wide //weight: 1
        $x_1_16 = {24 00 72 00 65 00 73 00 [0-48] 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00}  //weight: 1, accuracy: Low
        $x_1_17 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 72 00 65 00 73 00 74 00 6d 00 65 00 74 00 68 00 6f 00 64 00 [0-48] 2d 00 75 00 72 00 69 00 [0-48] 3b 00 [0-16] 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 [0-32] 24 00}  //weight: 1, accuracy: Low
        $x_1_18 = "iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_11_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_11_*) and 1 of ($x_10_*))) or
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
        $n_100_7 = "github.com" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
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
        $x_1_3 = {e2 00 80 00 95 00 77 00}  //weight: 1, accuracy: High
        $x_1_4 = {e2 00 80 00 94 00 77 00}  //weight: 1, accuracy: High
        $x_1_5 = {e2 00 80 00 93 00 77 00}  //weight: 1, accuracy: High
        $x_1_6 = "/w" wide //weight: 1
        $x_1_7 = "http" wide //weight: 1
        $n_100_8 = ".ps1" wide //weight: -100
        $n_100_9 = ".hta" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
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
        $x_10_3 = {e2 00 80 00 95 00 77 00}  //weight: 10, accuracy: High
        $x_10_4 = {e2 00 80 00 94 00 77 00}  //weight: 10, accuracy: High
        $x_10_5 = "/w" wide //weight: 10
        $x_1_6 = "http" wide //weight: 1
        $x_1_7 = "iex" wide //weight: 1
        $x_1_8 = "iwr" wide //weight: 1
        $n_300_9 = ".ps1" wide //weight: -300
        $n_300_10 = ".hta" wide //weight: -300
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
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
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = "2no.co/" wide //weight: 1
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
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_10_2 = {68 00 74 00 74 00 70 00 90 00 02 00 ff 00 2e 00 6f 00 67 00 67 00}  //weight: 10, accuracy: High
        $x_10_3 = {20 00 05 27 20 00}  //weight: 10, accuracy: High
        $n_100_4 = "msedgewebview2.exe" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
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
        $x_200_3 = {e2 00 80 00 95 00 77 00}  //weight: 200, accuracy: High
        $x_200_4 = {e2 00 80 00 94 00 77 00}  //weight: 200, accuracy: High
        $x_200_5 = "/w" wide //weight: 200
        $x_200_6 = {e2 00 80 00 93 00 77 00}  //weight: 200, accuracy: High
        $x_400_7 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-255] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_8 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 [0-255] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_9 = {63 00 6d 00 64 00 [0-48] 63 00 75 00 72 00 6c 00 [0-48] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_10 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-48] 63 00 75 00 72 00 6c 00 [0-48] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_11 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-32] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-32] 63 00 6d 00 64 00}  //weight: 400, accuracy: Low
        $x_400_12 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 [0-32] 63 00 6d 00 64 00}  //weight: 400, accuracy: Low
        $x_400_13 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-32] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-32] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 400, accuracy: Low
        $x_400_14 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-32] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-32] 77 00 6d 00 69 00 63 00}  //weight: 400, accuracy: Low
        $n_500_15 = ".ps1" wide //weight: -500
        $n_500_16 = ".hta" wide //weight: -500
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
        strings_accuracy = "Low"
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
        $x_1_11 = "handprintscariness.ru/" wide //weight: 1
        $x_1_12 = "e.overallwobbly.ru/" wide //weight: 1
        $x_1_13 = "levciavia.top/" wide //weight: 1
        $x_1_14 = "discountly.pw/" wide //weight: 1
        $x_1_15 = "session-cache-zx482.oss-ap-southeast-1.aliyuncs.com/" wide //weight: 1
        $x_1_16 = "yourcialsupply.top/" wide //weight: 1
        $x_1_17 = "ybfl.live/" wide //weight: 1
        $x_1_18 = "rekx.live/" wide //weight: 1
        $x_1_19 = "jasonstatham.pw/" wide //weight: 1
        $x_1_20 = "tomhanks.pw/" wide //weight: 1
        $x_1_21 = "travel.image-gene-saver.it.com" wide //weight: 1
        $x_1_22 = "http://10.1.69.25/m2" wide //weight: 1
        $x_1_23 = "finalstepgo.com/" wide //weight: 1
        $x_1_24 = "6t.czlw.ru" wide //weight: 1
        $x_1_25 = "v7q.pw/" wide //weight: 1
        $x_1_26 = "events-data-microsoft.com" wide //weight: 1
        $x_1_27 = "eventsdata-microsoft-live.com" wide //weight: 1
        $x_1_28 = "dnsg-windows-ds-data.com" wide //weight: 1
        $x_1_29 = "firewatches.quest" wide //weight: 1
        $x_1_30 = "finalstepgetshere.com" wide //weight: 1
        $x_1_31 = "funbunistica.b-cdn.net" wide //weight: 1
        $x_1_32 = "pltx11.b-cdn.net" wide //weight: 1
        $x_1_33 = "bokneg.com" wide //weight: 1
        $x_1_34 = "kolepz.com" wide //weight: 1
        $x_1_35 = "microsoft-iplcloud.live" wide //weight: 1
        $x_1_36 = "pullfile321.b-cdn.net" wide //weight: 1
        $x_1_37 = "tinselweaver.boats" wide //weight: 1
        $x_1_38 = "xilx222.b-cdn.net" wide //weight: 1
        $x_1_39 = "clouds-verify.com/" wide //weight: 1
        $x_1_40 = "clloudsverify.com/" wide //weight: 1
        $x_1_41 = "clloudverify.com/" wide //weight: 1
        $x_1_42 = "coreun.com/" wide //weight: 1
        $x_1_43 = {68 00 74 00 74 00 70 00 [0-255] 2f 00 77 00 70 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_44 = "11x1.ink" wide //weight: 1
        $x_1_45 = "10x07.ink" wide //weight: 1
        $x_1_46 = "22x2.xyz" wide //weight: 1
        $x_1_47 = "cmbkz8bui000008k22bcm3b3k.info" wide //weight: 1
        $x_1_48 = "tokennbkn.com" wide //weight: 1
        $x_1_49 = "zip-store.oss-ap-southeast-1.aliyuncs.com/" wide //weight: 1
        $x_1_50 = "yxyz.zyxy.org/" wide //weight: 1
        $x_1_51 = "www.svcrestartmod.icu/" wide //weight: 1
        $x_1_52 = "startupcheetah.com/" wide //weight: 1
        $x_1_53 = "sinofreights.com/" wide //weight: 1
        $x_1_54 = "finalsteptogo.com/" wide //weight: 1
        $x_1_55 = "mnvuz3gvy3.top/" wide //weight: 1
        $x_1_56 = "xilx222.b-cdn.net/" wide //weight: 1
        $x_1_57 = "oswyka.com/" wide //weight: 1
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
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "mshta" wide //weight: 2
        $x_2_3 = "curl" wide //weight: 2
        $x_5_4 = "http" wide //weight: 5
        $x_5_5 = {69 00 77 00 72 00 [0-48] 69 00 65 00 78 00 [0-255] 69 00 64 00 3a 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
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
        $x_10_14 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 79 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_15 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 61 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_16 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 69 00 67 00 69 00 74 00 61 00 6c 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_17 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_18 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 65 00 6d 00 70 00 6c 00 6f 00 79 00 65 00 72 00 64 00 62 00 7a 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_19 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 65 00 70 00 73 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_20 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 6f 00 72 00 65 00 73 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_21 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 6c 00 76 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_22 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 75 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_23 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 75 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_24 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 67 00 64 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_25 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 68 00 61 00 69 00 72 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_26 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 68 00 65 00 6c 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_27 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 69 00 63 00 75 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_28 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 69 00 6e 00 66 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_29 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 61 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_30 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 66 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_31 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 6e 00 6b 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_32 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 6f 00 61 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_33 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 76 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_34 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 66 00 64 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_35 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 66 00 64 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_36 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 34 00 61 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_37 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 64 00 62 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_38 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_39 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 70 00 33 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_40 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 70 00 34 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_41 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_42 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_43 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6f 00 72 00 67 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_44 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 61 00 72 00 74 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_45 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 72 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_46 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 77 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_47 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 61 00 63 00 69 00 6e 00 67 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_48 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_49 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 69 00 73 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_50 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 76 00 69 00 65 00 77 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_51 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 75 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_52 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 62 00 73 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_53 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_54 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 6f 00 6c 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_55 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 72 00 65 00 73 00 73 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_56 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 63 00 69 00 65 00 6e 00 63 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_57 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 68 00 6f 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_58 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 69 00 74 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_59 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 70 00 61 00 63 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_60 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 6f 00 72 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_61 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 72 00 65 00 61 00 6d 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_62 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 75 00 64 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_63 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 63 00 68 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_64 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_65 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 72 00 72 00 69 00 66 00 79 00 65 00 6e 00 79 00 62 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_66 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 6f 00 64 00 61 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_67 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 6f 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_68 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 76 00 69 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_69 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 77 00 6f 00 72 00 6b 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_70 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 77 00 6f 00 72 00 6c 00 64 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_71 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 78 00 6c 00 6c 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_72 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 78 00 79 00 7a 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_73 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 79 00 6f 00 6b 00 6f 00 68 00 61 00 6d 00 61 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_74 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 71 00 75 00 65 00 73 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $n_500_75 = ".ps1" wide //weight: -500
        $n_500_76 = ".hta" wide //weight: -500
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
        $x_1_7 = "pastebin" wide //weight: 1
        $x_1_8 = "pastes.io" wide //weight: 1
        $x_1_9 = "cutt.ly" wide //weight: 1
        $x_1_10 = "tinyurl.com" wide //weight: 1
        $x_1_11 = "rentry.co" wide //weight: 1
        $x_1_12 = "blogspot.com" wide //weight: 1
        $x_1_13 = "bit.ly" wide //weight: 1
        $x_1_14 = "psee.io" wide //weight: 1
        $x_1_15 = "files.catbox.moe" wide //weight: 1
        $x_1_16 = "nopaste.net/" wide //weight: 1
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
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "windowsinstaller.installer" wide //weight: 1
        $x_1_3 = "installer.installer" wide //weight: 1
        $x_1_4 = "uilevel" wide //weight: 1
        $x_1_5 = "installproduct" wide //weight: 1
        $x_2_6 = "($u.startswith('htps://')){$u.insert(2,'t')" wide //weight: 2
        $x_2_7 = {6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 2d 00 63 00 6f 00 6d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-80] 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 [0-48] 2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 [0-80] 75 00 69 00 6c 00 65 00 76 00 65 00 6c 00}  //weight: 2, accuracy: Low
        $x_1_8 = "%{[char][convert]::toint32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
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

rule Trojan_Win32_ClickFix_SIA_2147941234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SIA"
        threat_id = "2147941234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6d 00 64 00 [0-16] 2f 00 63 00 [0-48] 63 00 75 00 72 00 6c 00}  //weight: 10, accuracy: Low
        $x_10_2 = "http" wide //weight: 10
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "mshta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_YAR_2147941336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.YAR!MTB"
        threat_id = "2147941336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "303"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "curl.exe" wide //weight: 100
        $x_100_2 = "http" wide //weight: 100
        $x_100_3 = "cmd /c" wide //weight: 100
        $x_1_4 = "verify" wide //weight: 1
        $x_1_5 = "youre" wide //weight: 1
        $x_1_6 = "human" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DBT_2147941458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBT!MTB"
        threat_id = "2147941458"
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
        $x_10_2 = ")|%{$" wide //weight: 10
        $x_10_3 = "+=[char]($_+" wide //weight: 10
        $x_10_4 = ")};.(" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZGA_2147941490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZGA"
        threat_id = "2147941490"
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
        $x_200_3 = {e2 00 80 00 95 00 77 00}  //weight: 200, accuracy: High
        $x_200_4 = {e2 00 80 00 94 00 77 00}  //weight: 200, accuracy: High
        $x_200_5 = {e2 00 80 00 93 00 77 00}  //weight: 200, accuracy: High
        $x_200_6 = "/w" wide //weight: 200
        $x_400_7 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-255] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_8 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 [0-255] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_9 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-48] 63 00 75 00 72 00 6c 00}  //weight: 400, accuracy: Low
        $x_400_10 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-80] 69 00 77 00 72 00}  //weight: 400, accuracy: Low
        $x_400_11 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-48] 63 00 75 00 72 00 6c 00}  //weight: 400, accuracy: Low
        $x_400_12 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-48] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_13 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-48] 69 00 77 00 72 00 20 00 [0-80] 69 00 65 00 78 00 20 00 [0-255] 3a 00}  //weight: 400, accuracy: Low
        $x_400_14 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-255] 5e 00 [0-5] 5e 00 [0-80] 68 00 74 00 74 00 70 00}  //weight: 400, accuracy: Low
        $x_400_15 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 [0-32] 63 00 6d 00 64 00}  //weight: 400, accuracy: Low
        $x_400_16 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-32] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-32] 63 00 6d 00 64 00}  //weight: 400, accuracy: Low
        $x_400_17 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-32] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-32] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 400, accuracy: Low
        $x_400_18 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-32] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-32] 77 00 6d 00 69 00 63 00}  //weight: 400, accuracy: Low
        $n_600_19 = ".ps1" wide //weight: -600
        $n_600_20 = ".hta" wide //weight: -600
        $n_600_21 = "explorer http:" wide //weight: -600
        $n_600_22 = "\\application\\chrome.exe" wide //weight: -600
        $n_600_23 = ".nbsdev.co.uk" wide //weight: -600
        $n_600_24 = "([scriptblock]::Create([Microsoft.Win32.Registry]::GetValue" wide //weight: -600
        $n_600_25 = "PSAppDeployToolkit" wide //weight: -600
        $n_600_26 = "pwceur.sharepoint.com" wide //weight: -600
        $n_600_27 = "pwcinternal.com" wide //weight: -600
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_200_*))) or
            ((1 of ($x_400_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_YAP_2147941556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.YAP!MTB"
        threat_id = "2147941556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "301"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "PowerShell.exe" wide //weight: 100
        $x_100_2 = "Hidden " wide //weight: 100
        $x_100_3 = "htps://" wide //weight: 100
        $x_1_4 = "Insert(2,'t')" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_YAS_2147941557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.YAS!MTB"
        threat_id = "2147941557"
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
        $x_10_2 = "minimized " wide //weight: 10
        $x_10_3 = "mshta" wide //weight: 10
        $x_10_4 = "http" wide //weight: 10
        $x_10_5 = "Guard Access:" wide //weight: 10
        $x_1_6 = "Guardian Step. Code:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCC_2147941679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCC!MTB"
        threat_id = "2147941679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "conhost --headless" wide //weight: 100
        $x_10_2 = "wmic product call install 0" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DBV_2147941843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBV!MTB"
        threat_id = "2147941843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_1_2 = "-W h -C" wide //weight: 1
        $x_1_3 = "-W HiDdEn -C" wide //weight: 1
        $x_1_4 = "-WindowStyle hidden -Command" wide //weight: 1
        $x_1_5 = "-w minimized -c" wide //weight: 1
        $x_1_6 = "-w 1 -c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DCA_2147941844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCA!MTB"
        threat_id = "2147941844"
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
        $x_10_2 = ".rePlAce(" wide //weight: 10
        $x_10_3 = ".tosTrINg()" wide //weight: 10
        $x_1_4 = "-JoiN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCB_2147941845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCB!MTB"
        threat_id = "2147941845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "163"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_50_2 = "wscript $" wide //weight: 50
        $x_10_3 = "ActiveXObject(" wide //weight: 10
        $x_1_4 = ".split(" wide //weight: 1
        $x_1_5 = "reverse" wide //weight: 1
        $x_1_6 = ".join(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZMM_2147941856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZMM!MTB"
        threat_id = "2147941856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "105"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Completed without log notice" wide //weight: 100
        $x_5_2 = "powershell" wide //weight: 5
        $x_5_3 = "mshta" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_HE_2147941868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.HE!MTB"
        threat_id = "2147941868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "202"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "invoke-expression $script" wide //weight: 1
        $x_1_3 = "iex $script" wide //weight: 1
        $x_200_4 = "$script = Invoke-RestMethod -Uri" wide //weight: 200
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DCD_2147941961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCD!MTB"
        threat_id = "2147941961"
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
        $x_10_2 = "$env:tmp" wide //weight: 10
        $x_10_3 = "Expand-Archive" wide //weight: 10
        $x_10_4 = "-Force" wide //weight: 10
        $x_1_5 = "irm -Uri" wide //weight: 1
        $x_1_6 = "iwr -Uri" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DCH_2147941962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCH!MTB"
        threat_id = "2147941962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "-OutFile" wide //weight: 10
        $x_1_3 = "-W h -C" wide //weight: 1
        $x_1_4 = "-W HiDdEn -C" wide //weight: 1
        $x_1_5 = "-WindowStyle hidden -Command" wide //weight: 1
        $x_1_6 = "-w minimized -c" wide //weight: 1
        $x_1_7 = "-w 1 -c" wide //weight: 1
        $x_1_8 = {e2 00 80 00 95 00 57 00 20 00 68 00 20 00 2d 00 63 00}  //weight: 1, accuracy: High
        $x_1_9 = "-w h -NoP -c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZHC_2147942051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZHC!MTB"
        threat_id = "2147942051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ActiveXObject(" wide //weight: 1
        $x_1_2 = "..reverse" wide //weight: 1
        $x_1_3 = ".split(" wide //weight: 1
        $x_1_4 = ".join(" wide //weight: 1
        $x_1_5 = ";eval(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZMN_2147942052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZMN!MTB"
        threat_id = "2147942052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "]+$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZMP_2147942053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZMP!MTB"
        threat_id = "2147942053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ForEach-Object {[Convert]::ToByte($" wide //weight: 1
        $x_1_2 = ".Substring" wide //weight: 1
        $x_1_3 = ".GetString(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZMQ_2147942054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZMQ!MTB"
        threat_id = "2147942054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Read($" wide //weight: 1
        $x_1_2 = "Net.Sockets.TCPClient" wide //weight: 1
        $x_1_3 = ".GetStream(" wide //weight: 1
        $x_1_4 = "while" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZMR_2147942055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZMR!MTB"
        threat_id = "2147942055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-Headers" wide //weight: 1
        $x_1_2 = ".GetString($" wide //weight: 1
        $x_1_3 = ".content" wide //weight: 1
        $x_1_4 = "iex $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DBU_2147942057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBU!MTB"
        threat_id = "2147942057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "[ScRiPtBlOcK]::CrEaTe(" wide //weight: 10
        $x_1_3 = "-W h -C" wide //weight: 1
        $x_1_4 = "-W HiDdEn -C" wide //weight: 1
        $x_1_5 = "-WindowStyle hidden -Command" wide //weight: 1
        $x_1_6 = "-w minimized -c" wide //weight: 1
        $x_1_7 = "-w 1 -c" wide //weight: 1
        $n_1000_8 = "github.com" wide //weight: -1000
        $n_1000_9 = "raw.githubusercontent.com" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DBY_2147942058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBY!MTB"
        threat_id = "2147942058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "[string]::join(" wide //weight: 10
        $x_1_3 = "-w h -NoP -c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCI_2147942059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCI!MTB"
        threat_id = "2147942059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "c^ur^l.ex^e" wide //weight: 100
        $x_10_2 = "-k -Ss -X" wide //weight: 10
        $x_1_3 = "&& start /min" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCJ_2147942349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCJ!MTB"
        threat_id = "2147942349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "-k -Ss -X" wide //weight: 100
        $x_10_2 = "&& start /min" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCM_2147942350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCM!MTB"
        threat_id = "2147942350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "cmd /min /c" wide //weight: 100
        $x_1_2 = "-UseBasicParsing" wide //weight: 1
        $x_1_3 = "-useb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZMS_2147942424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZMS!MTB"
        threat_id = "2147942424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.Http.HttpClient]::new" wide //weight: 1
        $x_1_2 = "([ScriptBlock]::Create($" wide //weight: 1
        $x_1_3 = ".GetStringAsync(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_HI_2147942492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.HI!MTB"
        threat_id = "2147942492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "|iex #" wide //weight: 100
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "mshta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZZA_2147942526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZZA!MTB"
        threat_id = "2147942526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Invoke-Command ([ScriptBlock]::Create($_.Content" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZZB_2147942527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZZB!MTB"
        threat_id = "2147942527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "New-Object" wide //weight: 1
        $x_1_2 = "WinHttp.WinHttpRequest" wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = ".Send(" wide //weight: 1
        $x_1_5 = "iex $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZZC_2147942528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZZC!MTB"
        threat_id = "2147942528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iex $" wide //weight: 1
        $x_1_2 = "[System.Convert]::FromBase64String($" wide //weight: 1
        $x_1_3 = "Confirm access" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZC_2147942686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZC"
        threat_id = "2147942686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "powershell" wide //weight: 20
        $x_20_2 = "-w" wide //weight: 20
        $x_20_3 = "http" wide //weight: 20
        $n_500_4 = ".ps1" wide //weight: -500
        $n_500_5 = ".hta" wide //weight: -500
        $n_500_6 = "bp-pytrack" wide //weight: -500
        $n_500_7 = "localhost:" wide //weight: -500
        $n_700_8 = "\\edge\\application\\msedge.exe" wide //weight: -700
        $x_500_9 = "greed-warranty.digikex" wide //weight: 500
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_20_*))) or
            ((1 of ($x_500_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DCP_2147942687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCP!MTB"
        threat_id = "2147942687"
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
        $x_10_2 = ".ToCHaRarRay()" wide //weight: 10
        $x_10_3 = "[array]::Reverse($" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_HH_2147942784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.HH!MTB"
        threat_id = "2147942784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "151"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-W HiDdEn -C" wide //weight: 1
        $x_1_2 = "-WindowStyle hidden -Command" wide //weight: 1
        $x_1_3 = "-w minimized -c" wide //weight: 1
        $x_1_4 = "-w 1 -c" wide //weight: 1
        $x_1_5 = {e2 00 80 00 95 00 57 00 20 00 68 00 20 00 2d 00 63 00}  //weight: 1, accuracy: High
        $x_1_6 = "-w h -NoP -c" wide //weight: 1
        $x_50_7 = "-replace" wide //weight: 50
        $x_100_8 = "([Convert]::FromBase64String($" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZZD_2147942796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZZD!MTB"
        threat_id = "2147942796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".DownloadString($" wide //weight: 1
        $x_1_2 = "Net.WebClient" wide //weight: 1
        $x_1_3 = "[ScriptBlock]::Create($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZZG_2147942797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZZG!MTB"
        threat_id = "2147942797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ").Content | ForEach-Object { Invoke-Expression $" wide //weight: 1
        $x_1_2 = ").Content | ForEach-Object { iex $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_DAX_2147942875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAX!MTB"
        threat_id = "2147942875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "125"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = {73 00 74 00 61 00 72 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-2] 24 00}  //weight: 10, accuracy: Low
        $x_10_3 = "=$env:temp" wide //weight: 10
        $x_5_4 = "-outfile" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCS_2147942876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCS!MTB"
        threat_id = "2147942876"
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
        $x_1_4 = "iex $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCT_2147942877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCT!MTB"
        threat_id = "2147942877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "[ScRiPtBlOcK]::CrEaTe($" wide //weight: 10
        $x_1_3 = "New-Object Net.WebClient).DownloadString($" wide //weight: 1
        $n_1000_4 = "github.com" wide //weight: -1000
        $n_1000_5 = "raw.githubusercontent.com" wide //weight: -1000
        $n_1000_6 = "maven.scm" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCU_2147942878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCU!MTB"
        threat_id = "2147942878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "-nop -w 1 -EP Bypass -c" wide //weight: 10
        $x_1_3 = "New-Object $" wide //weight: 1
        $n_1000_4 = "github.com" wide //weight: -1000
        $n_1000_5 = "raw.githubusercontent.com" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCY_2147942897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCY!MTB"
        threat_id = "2147942897"
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
        $x_10_2 = "[Convert]::FromBase64String($" wide //weight: 10
        $x_10_3 = ".Length)]-join" wide //weight: 10
        $x_10_4 = "#Discord_code" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCZ_2147942898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCZ!MTB"
        threat_id = "2147942898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "Start-BitsTransfer (" wide //weight: 10
        $x_10_3 = "Start-'BitsTransfer' (" wide //weight: 10
        $x_1_4 = "$env:TEMP+'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DDA_2147942899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDA!MTB"
        threat_id = "2147942899"
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
        $x_10_2 = "-Window HID -c $" wide //weight: 10
        $x_10_3 = ".php?an=1';" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZZH_2147942983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZZH!MTB"
        threat_id = "2147942983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[IO.File]::ReadAllBytes($" wide //weight: 1
        $x_1_2 = "ForEach-Object { $_.ToString" wide //weight: 1
        $x_1_3 = "-join" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZZI_2147942984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZZI!MTB"
        threat_id = "2147942984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".replace('^'," wide //weight: 1
        $x_1_2 = ".replace('`'," wide //weight: 1
        $x_1_3 = ".replace('+'," wide //weight: 1
        $x_1_4 = ".replace('$'," wide //weight: 1
        $x_1_5 = ".replace('*'," wide //weight: 1
        $n_100_6 = "AVEVA" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_ZZR_2147942988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZZR!MTB"
        threat_id = "2147942988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $n_100_3 = "abcd" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCW_2147942994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCW!MTB"
        threat_id = "2147942994"
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
        $x_1_4 = "| iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCX_2147942995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCX!MTB"
        threat_id = "2147942995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "152"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_50_2 = "$a+$b+$c+$d" wide //weight: 50
        $x_1_3 = "New-Object Net.WebClient" wide //weight: 1
        $x_1_4 = ".DownloadFile($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DAD_2147943081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DAD!MTB"
        threat_id = "2147943081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_100_2 = ".shop" wide //weight: 100
        $x_100_3 = ".xyz" wide //weight: 100
        $x_100_4 = ".icu" wide //weight: 100
        $x_100_5 = ".lat" wide //weight: 100
        $x_100_6 = ".fun" wide //weight: 100
        $x_100_7 = ".bet" wide //weight: 100
        $x_100_8 = ".live" wide //weight: 100
        $x_100_9 = ".life" wide //weight: 100
        $x_100_10 = ".online" wide //weight: 100
        $x_100_11 = ".bond" wide //weight: 100
        $x_100_12 = ".top" wide //weight: 100
        $x_100_13 = ".world" wide //weight: 100
        $x_100_14 = ".click" wide //weight: 100
        $x_100_15 = ".forest" wide //weight: 100
        $x_100_16 = ".run" wide //weight: 100
        $x_100_17 = ".was" wide //weight: 100
        $x_100_18 = ".today" wide //weight: 100
        $x_100_19 = ".cyou" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_SHA_2147943279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SHA"
        threat_id = "2147943279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "curl" wide //weight: 1
        $x_1_3 = "[convert]::frombase64string" wide //weight: 1
        $x_1_4 = {7c 00 90 00 27 00 10 00 00 00 69 00 65 00 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_ClickFix_ABB_2147943280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ABB"
        threat_id = "2147943280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 100, accuracy: High
        $x_10_2 = "chatcdn" wide //weight: 10
        $x_10_3 = "duckdns" wide //weight: 10
        $x_10_4 = "digikex.com" wide //weight: 10
        $x_10_5 = "bodlsan.com" wide //weight: 10
        $x_10_6 = ".r2.dev" wide //weight: 10
        $x_10_7 = ".trycloudflare.com" wide //weight: 10
        $x_10_8 = "pastebin" wide //weight: 10
        $x_10_9 = "pastes.io" wide //weight: 10
        $x_10_10 = "cutt.ly" wide //weight: 10
        $x_10_11 = "tinyurl.com" wide //weight: 10
        $x_10_12 = "rentry.co" wide //weight: 10
        $x_10_13 = "blogspot.com" wide //weight: 10
        $x_10_14 = "bit.ly" wide //weight: 10
        $x_10_15 = "psee.io" wide //weight: 10
        $x_10_16 = "files.catbox.moe" wide //weight: 10
        $n_500_17 = "($instance -eq 'mssqlserver')" ascii //weight: -500
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((11 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_SFB_2147943281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SFB"
        threat_id = "2147943281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_100_2 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-255] 2e 00 6d 00 73 00 69 00}  //weight: 100, accuracy: Low
        $x_1_3 = "/q" wide //weight: 1
        $x_1_4 = "/i" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_SKDA_2147943282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SKDA"
        threat_id = "2147943282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "cmd.exe" wide //weight: 1
        $x_1_3 = {2e 00 70 00 68 00 70 00 [0-48] 2d 00 6f 00 [0-255] 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DBZ_2147943415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBZ!MTB"
        threat_id = "2147943415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_1_2 = "-W h -C" wide //weight: 1
        $x_1_3 = "-W HiDdEn -C " wide //weight: 1
        $x_1_4 = "/w h -C" wide //weight: 1
        $x_1_5 = "-w minimized -c" wide //weight: 1
        $x_1_6 = "-w 1 -c" wide //weight: 1
        $x_1_7 = {e2 00 80 00 95 00 57 00 20 00 68 00 20 00 2d 00 63 00}  //weight: 1, accuracy: High
        $x_1_8 = {2d 00 57 00 20 00 68 00 20 00 e2 00 80 00 94 00 43 00}  //weight: 1, accuracy: High
        $x_1_9 = "-w h -NoP -c" wide //weight: 1
        $x_1_10 = {e2 00 80 00 95 00 77 00 20 00 68 00 20 00 2f 00 63 00}  //weight: 1, accuracy: High
        $x_1_11 = {e2 00 80 00 95 00 77 00 20 00 68 00 20 00 e2 00 80 00 94 00 43 00}  //weight: 1, accuracy: High
        $x_1_12 = "/w h /C" wide //weight: 1
        $x_1_13 = "-w h -com" wide //weight: 1
        $x_1_14 = "-windowstyle h -c" wide //weight: 1
        $x_1_15 = "-wi 1 -com" wide //weight: 1
        $x_1_16 = "-window h -co" wide //weight: 1
        $x_1_17 = "-wi h -co" wide //weight: 1
        $x_1_18 = "-w h -command" wide //weight: 1
        $n_1000_19 = "github.com" wide //weight: -1000
        $n_1000_20 = "raw.githubusercontent.com" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DDD_2147943416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDD!MTB"
        threat_id = "2147943416"
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
        $x_10_2 = "$Env:temp\\" wide //weight: 10
        $x_10_3 = "wget -O $" wide //weight: 10
        $x_10_4 = "mshta" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDE_2147943417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDE!MTB"
        threat_id = "2147943417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-50] 2e 00 6d 00 73 00 69 00 20 00 2f 00 71 00 6e 00 [0-100] 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00}  //weight: 100, accuracy: Low
        $x_100_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-50] 2e 00 74 00 78 00 74 00 20 00 2f 00 71 00 6e 00 [0-100] 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00}  //weight: 100, accuracy: Low
        $x_100_3 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 71 00 6e 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-100] 2e 00 6d 00 73 00 69 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 71 00 6e 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00}  //weight: 100, accuracy: Low
        $x_100_4 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 71 00 6e 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-100] 2e 00 74 00 78 00 74 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 71 00 6e 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_DDG_2147943418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDG!MTB"
        threat_id = "2147943418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ").DownloadString(~htt" wide //weight: 1
        $x_1_2 = {c3 00 8e 00 45 00 58 00 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDG_2147943418_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDG!MTB"
        threat_id = "2147943418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "irm https" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-60] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = " iex" wide //weight: 1
        $x_100_4 = "bwdcc2" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDG_2147943418_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDG!MTB"
        threat_id = "2147943418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "161"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell -C" wide //weight: 100
        $x_50_2 = "{& (dir \\W*\\*32\\c??l.e*).Name" wide //weight: 50
        $x_10_3 = "| iex" wide //weight: 10
        $x_1_4 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDI_2147943419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDI!MTB"
        threat_id = "2147943419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "|Out-String" wide //weight: 10
        $x_1_3 = "curl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDI_2147943419_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDI!MTB"
        threat_id = "2147943419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".open('GET',$" wide //weight: 1
        $x_1_2 = "send()" wide //weight: 1
        $x_1_3 = ".response" wide //weight: 1
        $x_1_4 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZZX_2147943519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZZX!MTB"
        threat_id = "2147943519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wscript $" wide //weight: 1
        $x_1_2 = "$env:temp" wide //weight: 1
        $x_1_3 = "del $" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_AAH_2147943521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AAH!MTB"
        threat_id = "2147943521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDJ_2147943522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDJ!MTB"
        threat_id = "2147943522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&& ftp" wide //weight: 1
        $x_1_2 = "&& curl" wide //weight: 1
        $x_1_3 = "http" wide //weight: 1
        $x_1_4 = "service" wide //weight: 1
        $x_1_5 = ".log" wide //weight: 1
        $n_100_6 = "msedgewebview2.exe" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDJ_2147943522_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDJ!MTB"
        threat_id = "2147943522"
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
        $x_10_2 = "[scriptblock]::Create(" wide //weight: 10
        $x_10_3 = "Get-Clipboard) -join" wide //weight: 10
        $x_1_4 = "| clip; &" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCN_2147943608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCN!MTB"
        threat_id = "2147943608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_1_2 = "-\"w\" h -C" wide //weight: 1
        $x_1_3 = {e2 00 80 00 94 00 77 00 20 00 68 00 20 00 2d 00 22 00 43 00}  //weight: 1, accuracy: High
        $x_1_4 = "/w h /\"C" wide //weight: 1
        $x_1_5 = "-W h -C" wide //weight: 1
        $x_1_6 = "-W HiDdEn -C " wide //weight: 1
        $x_1_7 = "-w minimized -c" wide //weight: 1
        $x_1_8 = "-w 1 -c" wide //weight: 1
        $x_1_9 = "-w h -com" wide //weight: 1
        $x_1_10 = "-windowstyle h -c" wide //weight: 1
        $x_1_11 = "-wi 1 -com" wide //weight: 1
        $x_1_12 = "-window h -co" wide //weight: 1
        $x_1_13 = "-wi h -co" wide //weight: 1
        $x_1_14 = "-w h -command" wide //weight: 1
        $x_1_15 = {e2 00 80 00 95 00 77 00 20 00 68 00 20 00 e2 00 80 00 94 00 43 00}  //weight: 1, accuracy: High
        $x_1_16 = "/w h /C" wide //weight: 1
        $x_1_17 = {e2 00 80 00 95 00 57 00 20 00 68 00 20 00 2d 00 63 00}  //weight: 1, accuracy: High
        $x_1_18 = {2d 00 57 00 20 00 68 00 20 00 e2 00 80 00 94 00 43 00}  //weight: 1, accuracy: High
        $x_1_19 = "-w h -NoP -c" wide //weight: 1
        $x_1_20 = {e2 00 80 00 95 00 77 00 20 00 68 00 20 00 2f 00 63 00}  //weight: 1, accuracy: High
        $x_1_21 = "/w h -C" wide //weight: 1
        $n_1000_22 = "github.com" wide //weight: -1000
        $n_1000_23 = "raw.githubusercontent.com" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_ZQC_2147943702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZQC!MTB"
        threat_id = "2147943702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "105"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_5_2 = "ActiveXObject" wide //weight: 5
        $x_5_3 = ".Insert(" wide //weight: 5
        $x_5_4 = "vbscript:Execute(" ascii //weight: 5
        $x_5_5 = "::FromBase64String" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_AAC_2147943703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AAC!MTB"
        threat_id = "2147943703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "raw.github" wide //weight: 1
        $n_100_3 = "SecurityProtocol" wide //weight: -100
        $n_100_4 = "ServicePointManager" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_AAD_2147943704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AAD!MTB"
        threat_id = "2147943704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".msimsiexec /qn /i http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_AAF_2147943705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AAF!MTB"
        threat_id = "2147943705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 72 00 65 00 73 00 74 00 6d 00 65 00 74 00 68 00 6f 00 64 00 20 00 2d 00 75 00 72 00 69 00 20 00 24 00 [0-60] 3b 00 20 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_SEZA_2147943846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SEZA"
        threat_id = "2147943846"
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
        $x_10_14 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 79 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_15 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 61 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_16 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 69 00 67 00 69 00 74 00 61 00 6c 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_17 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_18 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 65 00 6d 00 70 00 6c 00 6f 00 79 00 65 00 72 00 64 00 62 00 7a 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_19 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 65 00 70 00 73 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_20 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 6f 00 72 00 65 00 73 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_21 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 6c 00 76 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_22 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 75 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_23 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 67 00 64 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_24 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 68 00 61 00 69 00 72 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_25 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 68 00 65 00 6c 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_26 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 69 00 63 00 75 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_27 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 69 00 6e 00 66 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_28 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 61 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_29 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 66 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_30 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 6e 00 6b 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_31 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 6f 00 61 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_32 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 76 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_33 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 3a 00 35 00 30 00 30 00 30 00 2f 00 62 00 6f 00 6f 00 74 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_34 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 66 00 64 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_35 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 75 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_36 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 34 00 61 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_37 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 64 00 62 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_38 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_39 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 70 00 33 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_40 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 70 00 34 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_41 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_42 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_43 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6f 00 72 00 67 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_44 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 61 00 72 00 74 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_45 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 72 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_46 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 77 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_47 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 61 00 63 00 69 00 6e 00 67 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_48 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_49 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 69 00 73 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_50 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 76 00 69 00 65 00 77 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_51 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 75 00 6e 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_52 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 62 00 73 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_53 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 6f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_54 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 6f 00 6c 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_55 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 72 00 65 00 73 00 73 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_56 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 63 00 69 00 65 00 6e 00 63 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_57 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 68 00 6f 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_58 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 69 00 74 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_59 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 70 00 61 00 63 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_60 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 6f 00 72 00 65 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_61 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 72 00 65 00 61 00 6d 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_62 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 75 00 64 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_63 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 63 00 68 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_64 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_65 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 72 00 72 00 69 00 66 00 79 00 65 00 6e 00 79 00 62 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_66 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 6f 00 64 00 61 00 79 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_67 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 6f 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_68 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 76 00 69 00 70 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_69 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 77 00 6f 00 72 00 6b 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_70 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 77 00 6f 00 72 00 6c 00 64 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_71 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 78 00 6c 00 6c 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_72 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 78 00 79 00 7a 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_73 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 79 00 6f 00 6b 00 6f 00 68 00 61 00 6d 00 61 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_74 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 61 00 63 00 74 00 69 00 76 00 69 00 74 00 79 00 64 00 6d 00 79 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_75 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 62 00 65 00 74 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_76 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 62 00 69 00 7a 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_77 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 62 00 6c 00 6f 00 67 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_78 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 62 00 6f 00 6e 00 64 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_79 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 62 00 75 00 7a 00 7a 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_80 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 61 00 6d 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_81 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 64 00 61 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_82 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 6c 00 69 00 63 00 6b 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_83 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 6c 00 75 00 62 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_84 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_85 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 75 00 6c 00 74 00 75 00 72 00 65 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_86 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 79 00 6f 00 75 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_87 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 79 00 6f 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_88 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 61 00 74 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_89 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 69 00 67 00 69 00 74 00 61 00 6c 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_90 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_91 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 65 00 6d 00 70 00 6c 00 6f 00 79 00 65 00 72 00 64 00 62 00 7a 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_92 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 65 00 70 00 73 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_93 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 6f 00 72 00 65 00 73 00 74 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_94 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 6c 00 76 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_95 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 66 00 75 00 6e 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_96 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 67 00 64 00 6e 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_97 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 68 00 61 00 69 00 72 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_98 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 68 00 65 00 6c 00 70 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_99 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 69 00 63 00 75 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_100 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 69 00 6e 00 66 00 6f 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_101 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 61 00 74 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_102 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 66 00 65 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_103 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 6e 00 6b 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_104 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 6f 00 61 00 6e 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_105 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 75 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_106 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 69 00 76 00 65 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_107 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 66 00 64 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_108 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 34 00 61 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_109 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 64 00 62 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_110 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 65 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_111 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 70 00 33 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_112 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 70 00 34 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_113 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6d 00 79 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_114 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_115 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6f 00 72 00 67 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_116 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 61 00 72 00 74 00 79 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_117 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 72 00 6f 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_118 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 77 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_119 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 61 00 63 00 69 00 6e 00 67 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_120 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 6e 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_121 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 69 00 73 00 65 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_122 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 65 00 76 00 69 00 65 00 77 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_123 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 75 00 6e 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_124 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 62 00 73 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_125 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 63 00 6f 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_126 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 6c 00 6f 00 6c 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_127 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 70 00 72 00 65 00 73 00 73 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_128 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 63 00 69 00 65 00 6e 00 63 00 65 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_129 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 68 00 6f 00 70 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_130 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 69 00 74 00 65 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_131 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 70 00 61 00 63 00 65 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_132 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 6f 00 72 00 65 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_133 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 72 00 65 00 61 00 6d 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_134 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 73 00 74 00 75 00 64 00 79 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_135 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 63 00 68 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_136 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 79 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_137 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 65 00 72 00 72 00 69 00 66 00 79 00 65 00 6e 00 79 00 62 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_138 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 6f 00 64 00 61 00 79 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_139 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 74 00 6f 00 70 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_140 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 76 00 69 00 70 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_141 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 77 00 6f 00 72 00 6b 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_142 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 77 00 6f 00 72 00 6c 00 64 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_143 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 78 00 6c 00 6c 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_144 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 78 00 79 00 7a 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_145 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 79 00 6f 00 6b 00 6f 00 68 00 61 00 6d 00 61 00 3f 00}  //weight: 10, accuracy: Low
        $x_10_146 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-32] 68 00 74 00 74 00 70 00 [0-48] 2e 00 71 00 75 00 65 00 73 00 74 00 3f 00}  //weight: 10, accuracy: Low
        $n_500_147 = ".ps1" wide //weight: -500
        $n_500_148 = ".hta" wide //weight: -500
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_SKC_2147943847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SKC"
        threat_id = "2147943847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = {73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 78 00 6d 00 6c 00 2e 00 78 00 6d 00 6c 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 3b 00 [0-48] 6c 00 6f 00 61 00 64 00 28 00 5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 74 00 65 00 78 00 74 00 2e 00 65 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 61 00 73 00 63 00 69 00 69 00 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 69 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = "|iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_SKE_2147943848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SKE"
        threat_id = "2147943848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_1_3 = {27 00 2b 00 27 00 [0-80] 27 00 2b 00 27 00 [0-80] 27 00 2b 00 27 00 [0-80] 27 00 2b 00 27 00}  //weight: 1, accuracy: Low
        $x_1_4 = {22 00 2b 00 22 00 [0-16] 22 00 2b 00 22 00 [0-48] 22 00 2b 00 22 00 [0-48] 22 00 2b 00 22 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 77 00 20 00 31 00 [0-255] 27 00 20 00 2b 00 20 00 27 00 [0-255] 27 00 20 00 2b 00 20 00 27 00 [0-255] 26 00 [0-16] 24 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2d 00 77 00 20 00 68 00 [0-255] 27 00 20 00 2b 00 20 00 27 00 [0-255] 27 00 20 00 2b 00 20 00 27 00 [0-255] 26 00 [0-16] 24 00}  //weight: 1, accuracy: Low
        $x_1_7 = {7b 00 30 00 7d 00 7b 00 31 00 7d 00 7b 00 32 00 7d 00 [0-80] 20 00 2d 00 66 00 20 00}  //weight: 1, accuracy: Low
        $x_1_8 = {5b 00 30 00 5d 00 [0-48] 5b 00 31 00 5d 00 [0-48] 5b 00 32 00 5d 00 [0-48] 5b 00 33 00 5d 00}  //weight: 1, accuracy: Low
        $x_11_9 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 [0-16] 63 00 6d 00 64 00 [0-255] 5e 00 [0-16] 5e 00 [0-16] 5e 00 [0-255] 2d 00 73 00}  //weight: 11, accuracy: Low
        $x_1_10 = {e2 00 80 00 94 00 57 00 20 00 68 00 [0-255] 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00}  //weight: 1, accuracy: Low
        $x_1_11 = {e2 00 80 00 94 00 57 00 20 00 68 00 [0-255] 2d 00 75 00 72 00 69 00}  //weight: 1, accuracy: Low
        $x_1_12 = {e2 00 80 00 95 00 77 00 20 00 68 00 [0-255] 2d 00 75 00 72 00 69 00}  //weight: 1, accuracy: Low
        $x_1_13 = "[string]::concat(('r','w','i')[" wide //weight: 1
        $x_1_14 = "[string]::concat(('x','e','i')[" wide //weight: 1
        $x_1_15 = {7c 00 25 00 7b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 24 00 5f 00 7d 00 29 00 2d 00 6a 00 6f 00 69 00 6e 00 27 00 27 00 [0-80] 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_1_16 = {28 00 5b 00 72 00 65 00 67 00 65 00 78 00 5d 00 3a 00 3a 00 6d 00 61 00 74 00 63 00 68 00 65 00 73 00 28 00 24 00 68 00 2c 00 27 00 2e 00 2e 00 27 00 29 00 7c 00 25 00 7b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 5b 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 74 00 6f 00 69 00 6e 00 74 00 33 00 32 00 28 00 24 00 5f 00 2e 00 76 00 61 00 6c 00 75 00 65 00 2c 00 31 00 36 00 29 00 7d 00 29 00 2d 00 6a 00 6f 00 69 00 6e 00 27 00 27 00 [0-255] 75 00 69 00 6c 00 65 00 76 00 65 00 6c 00}  //weight: 1, accuracy: Low
        $n_100_17 = "\\systemservices.ps1" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            ((1 of ($x_11_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_BBD_2147943963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBD!MTB"
        threat_id = "2147943963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-join ''" wide //weight: 1
        $x_1_3 = "';&$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBD_2147943963_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBD!MTB"
        threat_id = "2147943963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = ".replace('$'" wide //weight: 1
        $x_1_3 = ".replace('!'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBE_2147943964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBE!MTB"
        threat_id = "2147943964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = ".Split(',');$" wide //weight: 1
        $x_1_3 = "'+'" wide //weight: 1
        $n_100_4 = "CMW_Signaling_Tx" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_GLI_2147943965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GLI!MTB"
        threat_id = "2147943965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "'i','e','x'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_GLHD_2147943966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GLHD!MTB"
        threat_id = "2147943966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = ").Content)).Trim()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBC_2147944078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBC!MTB"
        threat_id = "2147944078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "$env:TEMP+''+" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_GLG_2147944087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GLG!MTB"
        threat_id = "2147944087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "%{[char]$_})-join" wide //weight: 1
        $x_1_3 = "';&$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DCQ_2147944089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DCQ!MTB"
        threat_id = "2147944089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "start \"\" /min \"cmd /c" wide //weight: 100
        $x_100_2 = "start /min cmd.exe /c" wide //weight: 100
        $x_10_3 = "&& call" wide //weight: 10
        $x_10_4 = "&&echo" wide //weight: 10
        $x_1_5 = "curl -L" wide //weight: 1
        $x_1_6 = "curl -s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DDM_2147944090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDM!MTB"
        threat_id = "2147944090"
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
        $x_10_3 = ".Content" wide //weight: 10
        $x_1_4 = "$env:_" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDM_2147944090_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDM!MTB"
        threat_id = "2147944090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 [0-16] 3b 00 69 00 72 00 6d 00 20 00 2d 00 75 00 72 00 69 00 20 00 27 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = "-Force" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_ZZN_2147944207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.ZZN!MTB"
        threat_id = "2147944207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pow^e" wide //weight: 1
        $x_1_2 = "p^owe" wide //weight: 1
        $x_1_3 = "p^o^w^e" wide //weight: 1
        $x_1_4 = "po^w^e" wide //weight: 1
        $x_1_5 = "p^owe^" wide //weight: 1
        $x_1_6 = "po^we" wide //weight: 1
        $x_1_7 = "p^ow^e" wide //weight: 1
        $x_1_8 = "powe^" wide //weight: 1
        $x_1_9 = "p^ow" wide //weight: 1
        $x_1_10 = "po^w" wide //weight: 1
        $x_1_11 = "pow^" wide //weight: 1
        $x_1_12 = "p^o^w" wide //weight: 1
        $n_100_13 = "HSBCPAY" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_BBG_2147944208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBG!MTB"
        threat_id = "2147944208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "i'+'e'+'x" wide //weight: 100
        $x_100_2 = "i'e'x" wide //weight: 100
        $x_100_3 = "i`e`x" wide //weight: 100
        $x_1_4 = "powershell" wide //weight: 1
        $n_100_5 = "msedgewebview2.exe" wide //weight: -100
        $n_100_6 = "ChromeUpdate" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_BBI_2147944209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBI!MTB"
        threat_id = "2147944209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[Convert]::FromBase64String($" wide //weight: 1
        $x_1_2 = "(&($" wide //weight: 1
        $x_1_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-255] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBJ_2147944210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBJ!MTB"
        threat_id = "2147944210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+(Get-Random)+" wide //weight: 1
        $x_1_2 = "$env:TEMP" wide //weight: 1
        $x_1_3 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_GVB_2147944234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GVB!MTB"
        threat_id = "2147944234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iex" wide //weight: 1
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "net.webclient" wide //weight: 10
        $x_10_4 = "download" wide //weight: 10
        $x_10_5 = "curl" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_GVD_2147944235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GVD!MTB"
        threat_id = "2147944235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "$appdata" wide //weight: 1
        $x_1_3 = "$chrome)" wide //weight: 1
        $x_1000_4 = "-UseBasicParsing).Content)" wide //weight: 1000
        $x_1000_5 = "forse restart" wide //weight: 1000
        $x_100_6 = "http" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*) and 1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_GVE_2147944236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GVE!MTB"
        threat_id = "2147944236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2401"
        strings_accuracy = "High"
    strings:
        $x_1000_1 = ".run('" wide //weight: 1000
        $x_1000_2 = "identifica" wide //weight: 1000
        $x_100_3 = "join-path $" wide //weight: 100
        $x_100_4 = "http" wide //weight: 100
        $x_100_5 = "start" wide //weight: 100
        $x_100_6 = "cscript" wide //weight: 100
        $x_1_7 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_GVF_2147944237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GVF!MTB"
        threat_id = "2147944237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "141"
        strings_accuracy = "High"
    strings:
        $x_100_1 = ".xyz" wide //weight: 100
        $x_40_2 = ".repLaCE(([ChAr]" wide //weight: 40
        $x_1_3 = "jOiN" wide //weight: 1
        $n_100_4 = "Cloud" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_GVG_2147944238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GVG!MTB"
        threat_id = "2147944238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1001"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_500_2 = "iex(irm($" wide //weight: 500
        $x_500_3 = {5b 00 73 00 74 00 72 00 69 00 6e 00 67 00 5d 00 24 00 [0-2] 2b 00 27 00 2e 00 27 00 2b 00 24 00 [0-2] 2b 00 27 00 2e 00 27 00 2b 00 24 00 [0-2] 2b 00 27 00 2e 00 27 00 2b 00 24 00 [0-2] 2b 00 24 00 [0-2] 3b 00}  //weight: 500, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_YAT_2147944322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.YAT!MTB"
        threat_id = "2147944322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "-w h" wide //weight: 10
        $x_10_3 = "-join" wide //weight: 10
        $x_10_4 = "New-Object Net.WebClient" wide //weight: 10
        $x_10_5 = "'DownloadStri'+'ng'" wide //weight: 10
        $x_10_6 = "'i'+'e'+'x'" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BSA_2147944439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BSA!MTB"
        threat_id = "2147944439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "env:AppData" wide //weight: 2
        $x_1_2 = "curl" wide //weight: 1
        $x_10_3 = "luckyseaworld.com/now.msi" wide //weight: 10
        $x_2_4 = "msiexec.exe /i" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBN_2147944467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBN!MTB"
        threat_id = "2147944467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 27 00 2b 00 27 00}  //weight: 1, accuracy: Low
        $x_1_2 = ").Content)" wide //weight: 1
        $x_1_3 = "'; &($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBO_2147944468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBO!MTB"
        threat_id = "2147944468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Length])-join'';$" wide //weight: 1
        $x_1_2 = "','')" wide //weight: 1
        $x_1_3 = "]+'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBQ_2147944469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBQ!MTB"
        threat_id = "2147944469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.Sockets.TCPClient" wide //weight: 1
        $x_1_2 = ".GetBytes($" wide //weight: 1
        $x_1_3 = ".Read($" wide //weight: 1
        $x_1_4 = "+(pwd).Path" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBR_2147944470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBR!MTB"
        threat_id = "2147944470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ")|%{[char]$_})-join'')" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = ")|%{&$_ (" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDC_2147944471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDC!MTB"
        threat_id = "2147944471"
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
        $x_10_2 = "WScript" wide //weight: 10
        $x_10_3 = ".DownloadFile($" wide //weight: 10
        $x_1_4 = "=$env:temp+" wide //weight: 1
        $x_1_5 = "=Join-Path $env:TEMP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DDC_2147944471_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDC!MTB"
        threat_id = "2147944471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "102"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http" wide //weight: 1
        $x_100_2 = "-Method Post).Content" wide //weight: 100
        $x_1_3 = "Invoke-Expression(Invoke-WebRequest -" wide //weight: 1
        $x_1_4 = "iex(Invoke-WebRequest -" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DDF_2147944472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDF!MTB"
        threat_id = "2147944472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {6d 00 73 00 68 00 74 00 61 00 [0-15] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-60] 3f 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDF_2147944472_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDF!MTB"
        threat_id = "2147944472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Start-Process" wide //weight: 1
        $x_1_2 = "https://youtu" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDL_2147944473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDL!MTB"
        threat_id = "2147944473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "catch{iex(curl" wide //weight: 1
        $x_1_2 = "iex(irm $" wide //weight: 1
        $x_1_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDL_2147944473_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDL!MTB"
        threat_id = "2147944473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "171"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_50_2 = "[ScRiPtBlOcK]::CrEaTe($" wide //weight: 50
        $x_10_3 = "-UseBasicParsing" wide //weight: 10
        $x_10_4 = ".Content" wide //weight: 10
        $x_1_5 = "-\"w\" h -C" wide //weight: 1
        $x_1_6 = {e2 00 80 00 94 00 77 00 20 00 68 00 20 00 2d 00 22 00 43 00 22 00}  //weight: 1, accuracy: High
        $x_1_7 = "-W h -C" wide //weight: 1
        $x_1_8 = "-W HiDdEn -C " wide //weight: 1
        $x_1_9 = "-w minimized -c" wide //weight: 1
        $x_1_10 = "-w 1 -c" wide //weight: 1
        $x_1_11 = "-w h -com" wide //weight: 1
        $x_1_12 = "-windowstyle h -c" wide //weight: 1
        $x_1_13 = "-wi 1 -com" wide //weight: 1
        $x_1_14 = "-window h -co" wide //weight: 1
        $x_1_15 = "-wi h -co" wide //weight: 1
        $x_1_16 = "-w h -command" wide //weight: 1
        $x_1_17 = {e2 00 80 00 95 00 77 00 20 00 68 00 20 00 e2 00 80 00 94 00 43 00}  //weight: 1, accuracy: High
        $x_1_18 = "/w h /C" wide //weight: 1
        $x_1_19 = {e2 00 80 00 95 00 57 00 20 00 68 00 20 00 2d 00 63 00}  //weight: 1, accuracy: High
        $x_1_20 = {2d 00 57 00 20 00 68 00 20 00 e2 00 80 00 94 00 43 00}  //weight: 1, accuracy: High
        $x_1_21 = "-w h -NoP -c" wide //weight: 1
        $x_1_22 = {e2 00 80 00 95 00 77 00 20 00 68 00 20 00 2f 00 63 00}  //weight: 1, accuracy: High
        $x_1_23 = "/w h -C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_10_*) and 11 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DDQ_2147944474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDQ!MTB"
        threat_id = "2147944474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = ")|%{[char]$_})-join" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDQ_2147944474_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDQ!MTB"
        threat_id = "2147944474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IO.File]::Create($" wide //weight: 1
        $x_1_2 = "[Net.WebRequest]::Create" wide //weight: 1
        $x_1_3 = ".CopyTo($" wide //weight: 1
        $x_1_4 = "Join-Path $" wide //weight: 1
        $x_1_5 = "replace" ascii //weight: 1
        $x_1_6 = "Start-Process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBF_2147944481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBF!MTB"
        threat_id = "2147944481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "[string]::Concat((" wide //weight: 1
        $x_1_3 = ".replace('!'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBT_2147944482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBT!MTB"
        threat_id = "2147944482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|%{$_.Content" wide //weight: 1
        $x_1_2 = "join" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBU_2147944600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBU!MTB"
        threat_id = "2147944600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-join([char[]]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DEB_2147944601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEB!MTB"
        threat_id = "2147944601"
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
        $x_10_2 = "&(gcM *wr)" wide //weight: 10
        $x_10_3 = "|&(gcm i*x)" wide //weight: 10
        $x_10_4 = "|iex" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_CCA_2147944690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCA!MTB"
        threat_id = "2147944690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "'iw' + 'r'" wide //weight: 1
        $x_1_2 = "'i' + 'wr'" wide //weight: 1
        $x_1_3 = "'ie' + 'x'" wide //weight: 1
        $x_1_4 = "'i' + 'ex'" wide //weight: 1
        $x_1_5 = "'i'+'ex'" wide //weight: 1
        $x_1_6 = "'ie'+'x'" wide //weight: 1
        $x_1_7 = "'iw'+'r'" wide //weight: 1
        $x_1_8 = "'i'+'wr'" wide //weight: 1
        $x_1_9 = "'i' + 'e' + 'x'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_CCC_2147944691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCC!MTB"
        threat_id = "2147944691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+[char]" wide //weight: 1
        $x_1_2 = "join" wide //weight: 1
        $x_1_3 = ".content" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCD_2147944692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCD!MTB"
        threat_id = "2147944692"
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
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = "'iex'" wide //weight: 1
        $x_1_4 = "'iwr'" wide //weight: 1
        $x_1_5 = ";&$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCD_2147944692_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCD!MTB"
        threat_id = "2147944692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-bxor" wide //weight: 1
        $x_1_2 = "ForEach-Object" wide //weight: 1
        $x_1_3 = "FromBase64String" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCK_2147944694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCK!MTB"
        threat_id = "2147944694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".DownloadFile($" wide //weight: 1
        $x_1_2 = ".Headers.Add(" wide //weight: 1
        $x_1_3 = "Net.WebClient" wide //weight: 1
        $x_1_4 = ");&$" wide //weight: 1
        $x_1_5 = "$env:TEMP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBBM_2147944703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBBM!MTB"
        threat_id = "2147944703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&& curl -k -o" wide //weight: 1
        $x_1_2 = "&& start" wide //weight: 1
        $x_1_3 = "&& echo" wide //weight: 1
        $x_1_4 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCN_2147944704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCN!MTB"
        threat_id = "2147944704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "msiexec" wide //weight: 10
        $x_10_2 = ".msi" wide //weight: 10
        $x_1_3 = "/q" wide //weight: 1
        $x_1_4 = "/package" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_CCO_2147944705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCO!MTB"
        threat_id = "2147944705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl" wide //weight: 1
        $x_1_2 = ".content" wide //weight: 1
        $x_1_3 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_SKD_2147944806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SKD"
        threat_id = "2147944806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = {20 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 90 00 02 00 ff 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: High
        $x_1_3 = " powershell " wide //weight: 1
        $x_1_4 = " powershell.exe " wide //weight: 1
        $n_100_5 = "\\application\\msedge.exe" wide //weight: -100
        $n_100_6 = "psappdeploytoolkit" wide //weight: -100
        $n_100_7 = "openwebsearch.cmd" wide //weight: -100
        $n_100_8 = "winget-autoupdate" wide //weight: -100
        $n_100_9 = "://inventory.kitenet.ch/pub" wide //weight: -100
        $n_100_10 = "([scriptblock]::Create([Microsoft.Win32.Registry]::GetValue" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_SKB_2147944807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SKB"
        threat_id = "2147944807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {e2 00 80 00 93 00}  //weight: 2, accuracy: High
        $x_2_3 = {e2 00 80 00 94 00}  //weight: 2, accuracy: High
        $x_2_4 = "invoke-restmethod" wide //weight: 2
        $x_2_5 = "invoke-expression" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_ClickFix_SKA_2147944808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SKA"
        threat_id = "2147944808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "400"
        strings_accuracy = "Low"
    strings:
        $x_200_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 200, accuracy: High
        $x_200_2 = "-w" wide //weight: 200
        $x_200_3 = {e2 00 80 00 95 00 77 00}  //weight: 200, accuracy: High
        $x_200_4 = {e2 00 80 00 94 00 77 00}  //weight: 200, accuracy: High
        $x_200_5 = "/w" wide //weight: 200
        $x_200_6 = {e2 00 80 00 93 00 77 00}  //weight: 200, accuracy: High
        $x_200_7 = "-\"w" wide //weight: 200
        $x_200_8 = {e2 00 80 00 95 00 22 00 77 00}  //weight: 200, accuracy: High
        $x_200_9 = {e2 00 80 00 94 00 22 00 77 00}  //weight: 200, accuracy: High
        $x_200_10 = "/\"w" wide //weight: 200
        $x_200_11 = {e2 00 80 00 93 00 22 00 77 00}  //weight: 200, accuracy: High
        $x_200_12 = "-'w" wide //weight: 200
        $x_200_13 = {e2 00 80 00 95 00 27 00 77 00}  //weight: 200, accuracy: High
        $x_200_14 = {e2 00 80 00 94 00 27 00 77 00}  //weight: 200, accuracy: High
        $x_200_15 = "/'w" wide //weight: 200
        $x_200_16 = {e2 00 80 00 93 00 27 00 77 00}  //weight: 200, accuracy: High
        $n_1000_17 = "ps1" wide //weight: -1000
        $n_1000_18 = {62 00 6c 00 6f 00 62 00 2e 00 63 00 6f 00 72 00 65 00 2e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 6e 00 65 00 74 00 [0-255] 72 00 65 00 70 00 6c 00 61 00 63 00 65 00}  //weight: -1000, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_ClickFix_SKZ_2147944809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.SKZ"
        threat_id = "2147944809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "130"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_20_2 = "-w" wide //weight: 20
        $x_20_3 = {e2 00 80 00 95 00 77 00}  //weight: 20, accuracy: High
        $x_20_4 = {e2 00 80 00 94 00 77 00}  //weight: 20, accuracy: High
        $x_20_5 = "/w" wide //weight: 20
        $x_20_6 = {e2 00 80 00 93 00 77 00}  //weight: 20, accuracy: High
        $x_20_7 = "-\"w" wide //weight: 20
        $x_20_8 = {e2 00 80 00 95 00 22 00 77 00}  //weight: 20, accuracy: High
        $x_20_9 = {e2 00 80 00 94 00 22 00 77 00}  //weight: 20, accuracy: High
        $x_20_10 = "/\"w" wide //weight: 20
        $x_20_11 = {e2 00 80 00 93 00 22 00 77 00}  //weight: 20, accuracy: High
        $x_20_12 = "-'w" wide //weight: 20
        $x_20_13 = {e2 00 80 00 95 00 27 00 77 00}  //weight: 20, accuracy: High
        $x_20_14 = {e2 00 80 00 94 00 27 00 77 00}  //weight: 20, accuracy: High
        $x_20_15 = "/'w" wide //weight: 20
        $x_20_16 = {e2 00 80 00 93 00 27 00 77 00}  //weight: 20, accuracy: High
        $x_100_17 = {69 00 72 00 6d 00 [0-255] 63 00 6c 00 69 00 70 00 [0-80] 28 00 5b 00 73 00 63 00 72 00 69 00 70 00 74 00 62 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-80] 67 00 65 00 74 00 2d 00 63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 29 00}  //weight: 100, accuracy: Low
        $x_100_18 = {63 00 6c 00 69 00 70 00 [0-96] 5b 00 73 00 63 00 72 00 69 00 70 00 74 00 62 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-80] 67 00 65 00 74 00 2d 00 63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 [0-80] 5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 65 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 5d 00 3a 00 3a 00 6e 00 65 00 77 00 6c 00 69 00 6e 00 65 00}  //weight: 100, accuracy: Low
        $x_100_19 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 72 00 65 00 73 00 74 00 6d 00 65 00 74 00 68 00 6f 00 64 00 [0-255] 2d 00 75 00 72 00 69 00 [0-255] 3b 00 [0-255] 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 27 30 30 00 24 00}  //weight: 100, accuracy: Low
        $x_130_20 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 [0-255] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 [0-255] 63 00 75 00 72 00 6c 00 20 00 68 00 74 00 74 00 70 00 [0-255] 66 00 74 00 70 00 [0-255] 2e 00 6c 00 6f 00 67 00}  //weight: 130, accuracy: Low
        $x_100_21 = {28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 2d 00 63 00 6f 00 6d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 29 00 2e 00 73 00 70 00 65 00 63 00 69 00 61 00 6c 00 66 00 6f 00 6c 00 64 00 65 00 72 00 73 00 28 00 27 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 27 00 29 00 [0-255] 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 2d 00 75 00 72 00 69 00}  //weight: 100, accuracy: Low
        $n_1000_22 = "quarkupdater" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((6 of ($x_20_*) and 1 of ($x_10_*))) or
            ((7 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_20_*))) or
            ((2 of ($x_100_*))) or
            ((1 of ($x_130_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DEG_2147944814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEG!MTB"
        threat_id = "2147944814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "130"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "[guid]::NewGuid()" wide //weight: 10
        $x_10_3 = "$env:TEMP" wide //weight: 10
        $x_10_4 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 28 00 [0-80] 24 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DEK_2147944815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEK!MTB"
        threat_id = "2147944815"
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
        $x_10_2 = "[guid]::NewGuid().ToString()" wide //weight: 10
        $x_10_3 = "$env:TEMP" wide //weight: 10
        $x_10_4 = "-OutFile $" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBV_2147944821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBV!MTB"
        threat_id = "2147944821"
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
        $x_1_2 = ";[Reflection.Assembly]::LoadWithPartialName(" wide //weight: 1
        $x_1_3 = "DownloadString($" wide //weight: 1
        $x_1_4 = "net.webclient" wide //weight: 1
        $x_1_5 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_BBBZ_2147944822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBBZ!MTB"
        threat_id = "2147944822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-60] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCF_2147944823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCF!MTB"
        threat_id = "2147944823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-bxor" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "for($" wide //weight: 1
        $x_1_4 = "FromBase64String($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCL_2147944824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCL!MTB"
        threat_id = "2147944824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "gi \\W*\\*32\\c??l.e" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCM_2147944825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCM!MTB"
        threat_id = "2147944825"
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
        $x_1_2 = "scriptblock]::create" wide //weight: 1
        $x_1_3 = "http" wide //weight: 1
        $x_1_4 = ".png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DM_2147944826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DM!MTB"
        threat_id = "2147944826"
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
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "Hidden" wide //weight: 10
        $x_10_4 = {53 00 74 00 61 00 72 00 74 00 [0-4] 50 00 72 00 6f 00 63 00 65 00 73 00 73 00}  //weight: 10, accuracy: Low
        $x_1_5 = "irm" wide //weight: 1
        $x_1_6 = "Invoke-RestMethod" wide //weight: 1
        $x_1_7 = "iwr" wide //weight: 1
        $x_1_8 = "Invoke-WebRequest" wide //weight: 1
        $x_1_9 = "iex" wide //weight: 1
        $x_1_10 = "Invoke-Expression" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_GVH_2147944827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.GVH!MTB"
        threat_id = "2147944827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "|iex" wide //weight: 1
        $n_100_3 = "github" wide //weight: -100
        $n_100_4 = "steam" wide //weight: -100
        $n_100_5 = "Read-Host" wide //weight: -100
        $n_100_6 = "ConvertFrom" wide //weight: -100
        $n_100_7 = "PassThru" wide //weight: -100
        $n_100_8 = "gitlab" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCJ_2147944949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCJ!MTB"
        threat_id = "2147944949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Net.Sockets.TCPClient" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCS_2147944950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCS!MTB"
        threat_id = "2147944950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "iex (Invoke-RestMethod" wide //weight: 10
        $x_10_2 = "invoke-expression (Invoke-RestMethod" wide //weight: 10
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_CCS_2147944950_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCS!MTB"
        threat_id = "2147944950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 68 00 69 00 6c 00 65 00 28 00 [0-16] 29 00 7b 00 74 00 72 00 79 00 7b 00}  //weight: 1, accuracy: Low
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = "-Method Post).Content" wide //weight: 1
        $x_10_4 = "Invoke-Expression(Invoke-WebRequest -Uri" wide //weight: 10
        $x_10_5 = "iex(Invoke-WebRequest -Uri" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DED_2147944951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DED!MTB"
        threat_id = "2147944951"
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
        $x_10_2 = "New-Object -ComObject WScript.Shell" wide //weight: 10
        $x_10_3 = ".SpecialFolders('Startup')" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DEM_2147944952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEM!MTB"
        threat_id = "2147944952"
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
        $x_10_2 = ".Headers.Add(" wide //weight: 10
        $x_10_3 = ".DownloadFile($" wide //weight: 10
        $x_1_4 = "=$env:temp+" wide //weight: 1
        $x_1_5 = "=Join-Path $env:TEMP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_CCB_2147945135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCB!MTB"
        threat_id = "2147945135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {27 00 29 00 2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 [0-16] 23 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCR_2147945137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCR!MTB"
        threat_id = "2147945137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 100, accuracy: Low
        $x_10_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 [0-32] 2d 00 75 00 73 00 65 00 62 00 61 00 73 00 69 00 63 00 70 00 61 00 72 00 73 00 69 00 6e 00 67 00 20 00 24 00 [0-32] 29 00 2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00}  //weight: 10, accuracy: Low
        $x_10_3 = {69 00 77 00 72 00 20 00 [0-32] 2d 00 75 00 73 00 65 00 62 00 61 00 73 00 69 00 63 00 70 00 61 00 72 00 73 00 69 00 6e 00 67 00 20 00 24 00 [0-32] 29 00 2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00}  //weight: 10, accuracy: Low
        $x_1_4 = "Invoke-Expression $" wide //weight: 1
        $x_1_5 = "iex $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DBD_2147945138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DBD!MTB"
        threat_id = "2147945138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_5_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 3a 00 [0-10] 2f 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DEN_2147945139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEN!MTB"
        threat_id = "2147945139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "/ge/boren" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCV_2147945257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCV!MTB"
        threat_id = "2147945257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ";iex (iwr $" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCX_2147945258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCX!MTB"
        threat_id = "2147945258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 27 00 2b 00 24 00 [0-16] 2b 00 27 00 3a 00 27 00 2b 00 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "h'+'t'+'t'+'p" wide //weight: 1
        $x_1_3 = "h '+' t '+' t' +' p" wide //weight: 1
        $x_1_4 = "ht'+'tp" wide //weight: 1
        $x_1_5 = "'h'+'tt'+'p" wide //weight: 1
        $x_1_6 = "htt'+'p" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_DEC_2147945259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEC!MTB"
        threat_id = "2147945259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "160"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_50_2 = {7b 00 26 00 20 00 28 00 64 00 69 00 72 00 20 00 [0-2] 5c 00 57 00 2a 00 [0-2] 5c 00 2a 00 33 00 32 00 [0-2] 5c 00 63 00 3f 00 3f 00 6c 00 2e 00 65 00 2a 00 29 00}  //weight: 50, accuracy: Low
        $x_10_3 = "| iex" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DEO_2147945260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEO!MTB"
        threat_id = "2147945260"
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
        $x_10_2 = "[Net.ServicePointManager]::SecurityProtocol=" wide //weight: 10
        $x_10_3 = "irm $" wide //weight: 10
        $x_1_4 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DEP_2147945261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEP!MTB"
        threat_id = "2147945261"
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
        $x_10_2 = "[System.Convert]::FromBase64String($" wide //weight: 10
        $x_10_3 = "[System.Text.Encoding]::UTF8.GetString(" wide //weight: 10
        $x_10_4 = "iex $cmd" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_EEA_2147945362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEA!MTB"
        threat_id = "2147945362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.webclient" wide //weight: 1
        $x_1_2 = "iex" wide //weight: 1
        $x_1_3 = "iwr" wide //weight: 1
        $x_1_4 = "invoke-webrequest" wide //weight: 1
        $x_100_5 = "5thed.christmas" wide //weight: 100
        $x_100_6 = "ui3.fit" wide //weight: 100
        $x_100_7 = "zeda1s.boutique" wide //weight: 100
        $x_100_8 = "px3.click/theme.iso" wide //weight: 100
        $x_100_9 = "walkin.college" wide //weight: 100
        $x_100_10 = "t0urist.cv" wide //weight: 100
        $x_100_11 = "otmuqi.com" wide //weight: 100
        $x_100_12 = "rizukimayamui-portfolio.info" wide //weight: 100
        $x_100_13 = "danili-myhomework.info" wide //weight: 100
        $x_100_14 = "-humancheck.info" wide //weight: 100
        $x_100_15 = "mylybnews.com" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_EED_2147945363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EED!MTB"
        threat_id = "2147945363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Verify you are human" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DEU_2147945364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEU!MTB"
        threat_id = "2147945364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "='iex';&" wide //weight: 10
        $x_10_3 = "='iex'; &" wide //weight: 10
        $x_1_4 = ".com/all.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DEX_2147945365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEX!MTB"
        threat_id = "2147945365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "PowerShell" wide //weight: 100
        $x_10_2 = "iex (Invoke-RestMethod" wide //weight: 10
        $x_10_3 = "dmvrfd.com" wide //weight: 10
        $x_1_4 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DEY_2147945366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEY!MTB"
        threat_id = "2147945366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "msiexec" wide //weight: 100
        $x_10_2 = "/norestart" wide //weight: 10
        $x_10_3 = "/package" wide //weight: 10
        $x_10_4 = "/passive" wide //weight: 10
        $x_1_5 = ".msi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DEW_2147945450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEW!MTB"
        threat_id = "2147945450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "=$env:TEMP+" wide //weight: 100
        $x_10_2 = "[guid]::NewGuid()" wide //weight: 10
        $x_10_3 = "[io.file]::WriteAllBytes($" wide //weight: 10
        $x_1_4 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DFA_2147945451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DFA!MTB"
        threat_id = "2147945451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.webclient" wide //weight: 1
        $x_100_2 = "5thed.christmas/upDate.iso" wide //weight: 100
        $x_100_3 = "zeda1s.boutique/uPdaTe.iso" wide //weight: 100
        $x_100_4 = "https://danili-myhomework.info" wide //weight: 100
        $x_100_5 = "samule.city" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DFC_2147945452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DFC!MTB"
        threat_id = "2147945452"
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
        $x_10_2 = "='ie'+$" wide //weight: 10
        $x_10_3 = "='ir'+$" wide //weight: 10
        $x_10_4 = "];&$" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCY_2147945456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCY!MTB"
        threat_id = "2147945456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Net.WebClient" wide //weight: 1
        $x_1_3 = ".DownloadString($" wide //weight: 1
        $x_1_4 = "';& $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCY_2147945456_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCY!MTB"
        threat_id = "2147945456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "=$env:temp +" wide //weight: 1
        $x_1_3 = "-uri $" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCY_2147945456_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCY!MTB"
        threat_id = "2147945456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Net.WebClient" wide //weight: 1
        $x_1_3 = ".DownloadString($" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
        $x_1_5 = "$env:TEMP" wide //weight: 1
        $x_1_6 = "join" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_CCY_2147945456_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.CCY!MTB"
        threat_id = "2147945456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.webclient" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = "download" wide //weight: 1
        $x_1_4 = "replace" wide //weight: 1
        $x_1_5 = ";foreach($" wide //weight: 1
        $x_1_6 = "Invoke-Item" wide //weight: 1
        $x_1_7 = "$env:temp+(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_EEC_2147945458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEC!MTB"
        threat_id = "2147945458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /create /tn" wide //weight: 1
        $x_1_2 = "$env:" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_EEF_2147945459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEF!MTB"
        threat_id = "2147945459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 20 00 2b 00 20 00 [0-32] 2e 00 76 00 62 00 73 00 27 00 3b 00 20 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 2d 00 75 00 72 00 69 00 20 00 24 00}  //weight: 10, accuracy: Low
        $x_10_2 = {24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 20 00 2b 00 20 00 [0-32] 2e 00 76 00 62 00 73 00 27 00 3b 00 20 00 69 00 77 00 72 00 20 00 2d 00 75 00 72 00 69 00 20 00 24 00}  //weight: 10, accuracy: Low
        $x_1_3 = ".php'; $" wide //weight: 1
        $x_1_4 = "powershell" wide //weight: 1
        $x_1_5 = "http" wide //weight: 1
        $x_1_6 = "-OutFile $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_BBS_2147945698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.BBS!MTB"
        threat_id = "2147945698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 [0-32] 2f 00 71 00 6e 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 61 00 6d 00 70 00 6c 00 65 00 73 00 73 00 2d 00 66 00 69 00 6c 00 65 00 73 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 [0-32] 2f 00 71 00 6e 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 6c 00 6c 00 6f 00 75 00 64 00 73 00 76 00 65 00 72 00 69 00 66 00 79 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-80] 76 00 65 00 72 00 69 00 66 00 79 00 2d 00 63 00 6c 00 69 00 65 00 6e 00 74 00 73 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-80] 63 00 6c 00 61 00 75 00 64 00 2d 00 63 00 6c 00 69 00 65 00 6e 00 74 00 73 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-80] 63 00 6c 00 2d 00 76 00 65 00 72 00 69 00 66 00 79 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_6 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-80] 76 00 66 00 2d 00 66 00 69 00 6c 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 [0-32] 2f 00 71 00 6e 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-60] 2e 00 73 00 68 00 69 00 65 00 6c 00 64 00 2e 00 6d 00 73 00 69 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_EEG_2147945699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEG!MTB"
        threat_id = "2147945699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-60] 76 00 65 00 72 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = "W*\\*32\\c??l.e" wide //weight: 1
        $x_1_3 = "Cloudflare Verification" wide //weight: 1
        $n_5_4 = "NationalSignatureVerificationSystem01.msi" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_EEH_2147945700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEH!MTB"
        threat_id = "2147945700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "'iex';&$" wide //weight: 100
        $x_100_2 = "'invoke-expression';&$" wide //weight: 100
        $x_1_3 = "Invoke-WebRequest';$" wide //weight: 1
        $x_1_4 = "iwr';$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_EEJ_2147945701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEJ!MTB"
        threat_id = "2147945701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "api.telegram.org/" wide //weight: 1
        $x_1_2 = "[Convert]::FromBase64String" wide //weight: 1
        $x_1_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DEQ_2147945702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEQ!MTB"
        threat_id = "2147945702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "cMd.ExE /V:ON /C" wide //weight: 100
        $x_10_2 = "mSh& set" wide //weight: 10
        $x_10_3 = "A.eXE&" wide //weight: 10
        $x_1_4 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DEZ_2147945704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DEZ!MTB"
        threat_id = "2147945704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "120"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "PowerShell" wide //weight: 100
        $x_10_2 = "\\W*\\*32\\c??l.e" wide //weight: 10
        $x_10_3 = "| iex" wide //weight: 10
        $n_1000_4 = "github.com" wide //weight: -1000
        $n_1000_5 = "raw.githubusercontent.com" wide //weight: -1000
        $n_1000_6 = "gitlab.com" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_EEI_2147945790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEI!MTB"
        threat_id = "2147945790"
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
        $x_10_2 = "[guid]::NewGuid()" wide //weight: 10
        $x_10_3 = "$env:TEMP" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_EEK_2147945791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEK!MTB"
        threat_id = "2147945791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "New-Object Net.WebClient;iex $" wide //weight: 1
        $x_1_2 = ".DownloadString($" wide //weight: 1
        $x_1_3 = "$env:TEMP" wide //weight: 1
        $x_1_4 = "-join '';$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_EEL_2147945792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEL!MTB"
        threat_id = "2147945792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".send();iex([Text.Encoding]::UTF8.GetString($" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-32] 3b 00 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_EEM_2147945793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEM!MTB"
        threat_id = "2147945793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 20 00 2b 00 20 00 [0-32] 2e 00 76 00 62 00 73 00 27 00 29 00 3b 00 20 00 73 00 74 00 61 00 72 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 24 00}  //weight: 10, accuracy: Low
        $x_10_2 = "Net.WebClient" wide //weight: 10
        $x_10_3 = ".DownloadFile" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_EEN_2147945921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEN!MTB"
        threat_id = "2147945921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "[System.IO.Path]::GetTempFileName()+'" wide //weight: 100
        $x_10_2 = "; & $" wide //weight: 10
        $x_10_3 = "hidden" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_EEO_2147945922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEO!MTB"
        threat_id = "2147945922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".send();iex([Text.Encoding]::UTF8.GetString($" wide //weight: 1
        $x_1_2 = "open('GET',$" wide //weight: 1
        $x_1_3 = "responseBody" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_EEP_2147945923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.EEP!MTB"
        threat_id = "2147945923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gwmi Win32_ComputerSystem" wide //weight: 1
        $x_1_2 = "#Verification Code" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DFG_2147946071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DFG!MTB"
        threat_id = "2147946071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "[guid]::NewGuid()" wide //weight: 100
        $x_10_2 = "curl" wide //weight: 10
        $x_1_3 = "=$env:APPDATA+" wide //weight: 1
        $x_1_4 = "=$env:TEMP+" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DFL_2147946181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DFL!MTB"
        threat_id = "2147946181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "/W**32c??l.e*" wide //weight: 100
        $x_100_2 = "W*\\*32\\c??l.e*" wide //weight: 100
        $x_10_3 = ".txt' | powershell" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DFM_2147946182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DFM!MTB"
        threat_id = "2147946182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "120"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {2e 00 73 00 65 00 6e 00 64 00 28 00 29 00 3b 00 [0-50] 5b 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 55 00 54 00 46 00 38 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00}  //weight: 100, accuracy: Low
        $x_10_2 = "open('GET',$" wide //weight: 10
        $x_10_3 = "responseBody" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DFO_2147946183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DFO!MTB"
        threat_id = "2147946183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "130"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = ".send();iex($" wide //weight: 100
        $x_10_2 = "open('GET',$" wide //weight: 10
        $x_10_3 = "responseText" wide //weight: 10
        $x_10_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-32] 3b 00 24 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDR_2147946200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDR!MTB"
        threat_id = "2147946200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|iex #Pass Verification Acces" wide //weight: 1
        $x_1_2 = "|invoke-expression #Pass Verification Access" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClickFix_MY_2147946332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.MY!MTB"
        threat_id = "2147946332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = ".php" wide //weight: 1
        $x_1_4 = "'w'+'sc'+'r'+'ipt" wide //weight: 1
        $x_1_5 = "'ra'+'mdata" wide //weight: 1
        $x_1_6 = "cur'+'l.e'+'xe" wide //weight: 1
        $x_1_7 = "'s'+'cht' + 'asks'" wide //weight: 1
        $x_1_8 = "cre'+'ate" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDK_2147946383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDK!MTB"
        threat_id = "2147946383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "|%{[char]$_})-join'" wide //weight: 100
        $x_1_2 = "iex $" wide //weight: 1
        $x_1_3 = "invoke-expresssion $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DDO_2147946384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDO!MTB"
        threat_id = "2147946384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[ProcessInjector.Program]::Main()" wide //weight: 1
        $x_1_2 = "Net.WebClient" wide //weight: 1
        $x_1_3 = "DownloadString" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDP_2147946385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDP!MTB"
        threat_id = "2147946385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "New-Object Net.WebClient;Invoke-Expression $" wide //weight: 10
        $x_10_2 = "DownloadString('http" wide //weight: 10
        $x_10_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 10, accuracy: Low
        $x_1_4 = "hidden" wide //weight: 1
        $x_1_5 = "-WindowStyle H" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClickFix_DFE_2147946485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DFE!MTB"
        threat_id = "2147946485"
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
        $x_10_2 = "=$env:APPDATA+" wide //weight: 10
        $x_10_3 = ".DownloadFile($" wide //weight: 10
        $x_10_4 = "$a+$b+$c+$d" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DFS_2147946486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DFS!MTB"
        threat_id = "2147946486"
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
        $x_10_2 = "[console]::SetWindowSize(" wide //weight: 10
        $x_10_3 = "iex([IO.StreamReader]::new([Net.WebRequest]::Create(" wide //weight: 10
        $x_10_4 = ".ReadToEnd();$" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DFX_2147946488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DFX!MTB"
        threat_id = "2147946488"
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
        $x_10_2 = "; &(gcm $" wide //weight: 10
        $x_10_3 = "='*wr';" wide //weight: 10
        $x_1_4 = "|&$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DFY_2147946489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DFY!MTB"
        threat_id = "2147946489"
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
        $x_10_2 = "[ScriptBlock]::Create(" wide //weight: 10
        $x_10_3 = "/HWID" wide //weight: 10
        $x_10_4 = "/Ohook" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_AAAG_2147946512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.AAAG!MTB"
        threat_id = "2147946512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&& curl" wide //weight: 1
        $x_1_2 = ".log" wide //weight: 1
        $x_1_3 = "&& ftp" wide //weight: 1
        $x_1_4 = "http" wide //weight: 1
        $n_100_5 = "awpdc.com" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDS_2147946513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDS!MTB"
        threat_id = "2147946513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Net.WebClient" wide //weight: 1
        $x_1_2 = ".UploadString($" wide //weight: 1
        $x_1_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDT_2147946514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDT!MTB"
        threat_id = "2147946514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "iex((get-clipboard -raw).substring(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDT_2147946514_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDT!MTB"
        threat_id = "2147946514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "Net.WebClient" wide //weight: 1
        $x_1_3 = "); # " wide //weight: 1
        $x_1_4 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClickFix_DDU_2147946515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClickFix.DDU!MTB"
        threat_id = "2147946515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "[Windows.Clipboard]::SetText([DateTime]::UtcNow.ToString" wide //weight: 1
        $x_1_3 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

