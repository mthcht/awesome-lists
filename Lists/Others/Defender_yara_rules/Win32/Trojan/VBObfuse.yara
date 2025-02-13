rule Trojan_Win32_VBObfuse_ARA_2147745820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.ARA!eml"
        threat_id = "2147745820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "QHpG1c0NhYtpGflYIgdKpraBVQm231" wide //weight: 2
        $x_5_2 = "aaa_TouchMeNot_.txt" ascii //weight: 5
        $x_5_3 = "FRYEd.exe" wide //weight: 5
        $x_2_4 = "FILLErMall" wide //weight: 2
        $x_1_5 = "gATlfopcEx9EzgJ45" wide //weight: 1
        $x_3_6 = "F1fpjBdzVJ733" wide //weight: 3
        $x_3_7 = "OkZ8k1uaUw86" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBObfuse_AFF_2147749952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.AFF!eml"
        threat_id = "2147749952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c3 88 06 5e 5b c3 [0-31] e8 [0-47] 43 81 fb c2 55 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SK_2147750021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SK!MTB"
        threat_id = "2147750021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "O764oW7UwRMR68255" wide //weight: 1
        $x_1_2 = "n7QXbvxDaKt7593h9EJP0Q9U220" wide //weight: 1
        $x_1_3 = "E1Bd2zfRKM8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SS_2147750022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SS!MTB"
        threat_id = "2147750022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UlNSjbqNoE9wPNDy73" wide //weight: 1
        $x_1_2 = "puZIANVKkipyiqdFvl1XWwop6Gdd88" wide //weight: 1
        $x_1_3 = "rkWf4MLq114" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SA_2147750023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SA!MTB"
        threat_id = "2147750023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ICsL5jf4rJMm8afR63r5pAKAPHy4U4Mz7DKYj126" wide //weight: 1
        $x_1_2 = "BrUu0aehy0DGOZwLFnHozEko6JaSVAU0JU0KCbA5125" wide //weight: 1
        $x_1_3 = "ilvc76" wide //weight: 1
        $x_1_4 = "G18UVJSb59" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SB_2147750044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SB!MTB"
        threat_id = "2147750044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "N0hSj0VmQK0uFUOp82269ZrqWEEr4148" wide //weight: 1
        $x_1_2 = "EshO3XSZWnB0slrzS4vP0fCUN22zgsucCZsXDiD75" wide //weight: 1
        $x_1_3 = "mNMU11" wide //weight: 1
        $x_1_4 = "zJocRkx78" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SC_2147750045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SC!MTB"
        threat_id = "2147750045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Z9miGb7GO6H903sfRllGyrG0NneyRhoE6fL4v76" wide //weight: 1
        $x_1_2 = "ah3xbAeYcUtP3chIR63" wide //weight: 1
        $x_1_3 = "EfsBPhVJ27pAN9t3GPGWEldmEPxqCAs187" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_CS_2147750050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.CS!eml"
        threat_id = "2147750050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 14 18 81 fe fb 16 0d 9e}  //weight: 1, accuracy: High
        $x_1_2 = {31 f2 81 fe 36 b1 0d 9e 75 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SD_2147750116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SD!MTB"
        threat_id = "2147750116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lvoMSyAubveg3FLN8yW0yon371" wide //weight: 1
        $x_1_2 = "RiJm0e7WrJpRtsZ70hxH192" wide //weight: 1
        $x_1_3 = "MU78PtA99" wide //weight: 1
        $x_1_4 = "xfMFdT9UMEKMoqU84q3wHjfveA766cOC200" wide //weight: 1
        $x_1_5 = "CbUa4zSayQ0aGl6gr8195" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SE_2147750117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SE!MTB"
        threat_id = "2147750117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PaioPMQOErR57o6fdytV8bGeA221" wide //weight: 1
        $x_1_2 = "HCxrJ5LjPTdntIQupgflTX2GYGj140" wide //weight: 1
        $x_1_3 = "ccpxCXjAvuxOnq9QVa8y48dyxvXYw45tB80" wide //weight: 1
        $x_1_4 = "aRdkbZB6iypouXvpJzR6JCOcQlHui128" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SM_2147750669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SM!MTB"
        threat_id = "2147750669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff 34 17 81 fa b4 78 b5 47 81 fb 66 33 e2 b3 5b 66 f7 c2 3c 9f 66 81 fb a6 af 31 f3 66 f7 c3 2e 1a 66 3d 6d 62 01 1c 10 81 fa f4 94 8e 4c 81 ff b6 d6 8e 70 83 c2 04 81 ff 9a 4c 5d 06 66 f7 c2 b1 42 81 fa 74 3c 00 00 75 b6}  //weight: 2, accuracy: High
        $x_2_2 = {ff 34 17 a9 ee ff 45 a1 66 f7 c2 ae 5d 5b 81 ff a8 87 00 05 81 fa 21 e3 ab 5a 31 f3 f7 c7 84 36 15 f9 66 3d 89 f0 01 1c 10 66 a9 39 31 81 ff 27 9c 4b 96 83 c2 04 f7 c7 a7 28 b3 40 f7 c3 5a b1 19 78 81 fa f8 3c 00 00 75 b6}  //weight: 2, accuracy: High
        $x_1_3 = "nIxvtqIoZJzOYh11" wide //weight: 1
        $x_1_4 = "Uslingegerningen6" wide //weight: 1
        $x_1_5 = "MyAHb189" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBObfuse_SN_2147750670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SN!MTB"
        threat_id = "2147750670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 34 17 3d 1b df c1 05 66 f7 c3 a8 f7 5b 66 a9 a2 50 66 81 fb a8 0f 31 f3 66 f7 c3 33 9c 66 a9 d6 b4 01 1c 10 f7 c2 da e7 46 41 66 81 fb e4 59 83 c2 04 66 3d 18 38 66 81 fb ef bb 81 fa 04 3c 00 00 75}  //weight: 1, accuracy: High
        $x_1_2 = {ff 34 17 f7 c7 c4 73 9c 34 f7 c7 f7 e1 c8 4d 5b 66 81 ff 84 91 f7 c2 a2 54 2b 18 31 f3 3d d0 9b 27 b1 f7 c2 03 2e 2b e0 01 1c 10 66 81 fa a2 ef 81 fb 60 84 b8 ef 83 c2 04 f7 c3 3b 08 a5 85 a9 44 ea 3f 78 81 fa 7c 3d 00 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_VBObfuse_SO_2147750722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SO!eml"
        threat_id = "2147750722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "nJ5HXneeIdErX5mzZ13" wide //weight: 3
        $x_3_2 = "llDUMtbDIAoD4HJP9J2YJcf54" wide //weight: 3
        $x_1_3 = "pYc8e9Tyzu2Uu8hY8QnmiFbfZS3or0ormksnjrv34" wide //weight: 1
        $x_1_4 = "paqwjBVR4jajqk6Q3ZL9s4STccFeltUBdkkG93" wide //weight: 1
        $x_1_5 = "sjCXgSbG9mxtus9fA5M2tWWy1cF9gBjVYDW7u8157" wide //weight: 1
        $x_1_6 = "QaGCx2u8pqt3rjdOjkpL92Wudpr147" wide //weight: 1
        $x_1_7 = "rCaVn81yfqFigXxrNDM6RB193" wide //weight: 1
        $x_1_8 = "qEbpWIoNXi2VHZpGZFY61" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBObfuse_SZ_2147750966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SZ!MTB"
        threat_id = "2147750966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aEs75QgRA244" wide //weight: 1
        $x_1_2 = "OAk166" wide //weight: 1
        $x_1_3 = "Prologscentra1" wide //weight: 1
        $x_1_4 = "karyoplasmindtrngevarmeskaberaadfrebl" wide //weight: 1
        $x_1_5 = "Forfriskheartstringsnonindustrial" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_ARG_2147750975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.ARG!eml"
        threat_id = "2147750975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 75 c0 8b fc a5 a5 a5 a5 8b 45 08 8b 00 ff 75 08 ff 90 b0 02 00 00 db e2 89 45 ac 83 7d ac 00 7d 1a}  //weight: 5, accuracy: High
        $x_1_2 = {81 f7 1e 59 1f 12}  //weight: 1, accuracy: High
        $x_1_3 = {81 f6 b6 98 f2 e3}  //weight: 1, accuracy: High
        $x_1_4 = {81 f6 dc 30 79 9f}  //weight: 1, accuracy: High
        $x_1_5 = {81 f7 6f 25 46 6a}  //weight: 1, accuracy: High
        $x_1_6 = {81 f6 50 82 ea 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBObfuse_ACE_2147752229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.ACE!MTB"
        threat_id = "2147752229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c timeout.exe /T 10 & Del" wide //weight: 1
        $x_1_2 = "ch.exe" wide //weight: 1
        $x_1_3 = "taskkill /im" wide //weight: 1
        $x_1_4 = "oy7oel014pgx3rnmgo1floytt4o8eghapzuon70fhru0lnlsvl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SV_2147752460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SV!MTB"
        threat_id = "2147752460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RYiW7rnBMReUrpbykyAVzV101" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SKK_2147752637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SKK!MTB"
        threat_id = "2147752637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f 6e da 81 fa 64 75 c3 64 31 f2 85 d2 c3}  //weight: 2, accuracy: High
        $x_2_2 = {0f 6e da 66 85 d2 31 f2}  //weight: 2, accuracy: High
        $x_1_3 = "pCLfAQb3aiuk2SoZcapx0GhPFmzb1bD29" wide //weight: 1
        $x_1_4 = "HKA44" wide //weight: 1
        $x_1_5 = "dkGu181" wide //weight: 1
        $x_1_6 = "OukTXIYkPMUkDcryIXt227" wide //weight: 1
        $x_1_7 = "Yat6V7xs182" wide //weight: 1
        $x_1_8 = "fucoOH5qRsmeQsM2238" wide //weight: 1
        $x_1_9 = "uuQjb0HNY59" wide //weight: 1
        $x_1_10 = "JMUUc7WS93" wide //weight: 1
        $x_1_11 = "x5CE32u8Ep91ELgrpDyeiq1r241" wide //weight: 1
        $x_1_12 = "oX6k74eQarLAeEhOm0btB141" wide //weight: 1
        $x_2_13 = "GiL7Dslp0ZbO7S6zCfzK186" wide //weight: 2
        $x_1_14 = "rpbNmQvakN17" wide //weight: 1
        $x_1_15 = "jUgKSezeqHXU213" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBObfuse_SSV_2147752643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SSV!MTB"
        threat_id = "2147752643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 24 83 c1 01 c3 30 00 66 0f 6e [0-8] 81 34 08}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 3b 00 00 00 66 0f 6e [0-3] 66 0f 6e [0-23] 41 66 0f 6e [0-4] 66 0f 6e [0-2] 41 66 0f 6e [0-2] 66 0f 6e [0-2] 3b 8d 94 00 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = "Eat9IRO2BRafoo59RJ3sFrL3WJR6YeMojVS144" wide //weight: 1
        $x_1_4 = "zzC3T4S9czoMVMNGawuaiItOQLj81" wide //weight: 1
        $x_1_5 = "mQfD8jGYjjfT24xAqFA8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_VBObfuse_SCO_2147752789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SCO!MTB"
        threat_id = "2147752789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "phcO3x776JMF62cJgCprk90nyxMvb0215" wide //weight: 1
        $x_1_2 = "XeKjG5iC8TJ31ZlGRtcuDSXwT145" wide //weight: 1
        $x_1_3 = "Q8pUkyVjzLISeTdULCdCR0mA1yVwvxT7sC6nhDR145" wide //weight: 1
        $x_1_4 = "lfzcs95" wide //weight: 1
        $x_1_5 = "CV5AEnisGyeyYeR0VIwMo5nB8BWTBp3b0w0Iv22" wide //weight: 1
        $x_1_6 = "rNol9YbbiKsRV52wW178" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SSA_2147753013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SSA!MTB"
        threat_id = "2147753013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IpWrNC6MCTrxbVpMmZIBRG74GYn89" wide //weight: 1
        $x_1_2 = "hXcBg6Iq176" wide //weight: 1
        $x_1_3 = "Nc2VIR3XvZkpBIv7XmFHoP7XYgxKIVd230" wide //weight: 1
        $x_1_4 = "D1kdDSyrpib66108" wide //weight: 1
        $x_1_5 = "EShdGrMmxdOAepJD0AU8y1E5rj9EOkW545" wide //weight: 1
        $x_1_6 = "NYM33PEqjiPncuO0Rb4raFAjzLBsOiDT9sJ1M130" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_RA_2147755686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.RA!MTB"
        threat_id = "2147755686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "C:\\Archivos de programa\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_2_3 = "\\Programas\\Ejecutables\\CoveCost.exe" wide //weight: 2
        $x_2_4 = "\\Setup\\RunTime.exe" wide //weight: 2
        $x_2_5 = "Program: DEPURADORTRXFD.EXE" wide //weight: 2
        $x_2_6 = "DepuraTrFD.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBObfuse_CY_2147899298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.CY!MTB"
        threat_id = "2147899298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 19 81 fa 3f ab 31 be 75 08}  //weight: 1, accuracy: High
        $x_1_2 = {31 f3 81 fb 80 93 ac 9d 75 08}  //weight: 1, accuracy: High
        $x_1_3 = {01 1c 10 81 fa 39 5f 87 8b 75 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBObfuse_SY_2147899299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBObfuse.SY!MTB"
        threat_id = "2147899299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBObfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RYiW7rnBMReUrpbykyAVzV101" wide //weight: 1
        $x_1_2 = "Eksam1" ascii //weight: 1
        $x_1_3 = "Stikla6" ascii //weight: 1
        $x_1_4 = "Sekstenaar7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

