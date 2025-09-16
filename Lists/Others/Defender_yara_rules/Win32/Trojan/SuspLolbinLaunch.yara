rule Trojan_Win32_SuspLolbinLaunch_A_2147768657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!at"
        threat_id = "2147768657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "at: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\at.exe" wide //weight: 1
        $x_1_2 = " at " wide //weight: 1
        $x_1_3 = "/interactive" wide //weight: 1
        $x_1_4 = "/computername \\\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_A_2147768658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!schtasks"
        threat_id = "2147768658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "schtasks: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $n_10_3 = "/run" wide //weight: -10
        $n_10_4 = "Diagnosis\\ZuumMonitoring" wide //weight: -10
        $n_10_5 = "AlertusSecureDesktopLauncher" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_A_2147768658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!schtasks"
        threat_id = "2147768658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "schtasks: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = " /Create " wide //weight: 1
        $x_1_3 = " /SC ONSTART " wide //weight: 1
        $x_1_4 = {20 00 2f 00 52 00 55 00 20 00 [0-4] 4e 00 54 00 20 00 41 00 55 00 54 00 48 00 4f 00 52 00 49 00 54 00 59 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00}  //weight: 1, accuracy: Low
        $x_1_5 = {20 00 2f 00 54 00 4e 00 20 00 29 20 20 00 20 00}  //weight: 1, accuracy: Low
        $x_1_6 = {20 00 2f 00 54 00 52 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-8] 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_7 = {20 00 2f 00 54 00 52 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-8] 5c 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspLolbinLaunch_A_2147768659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!atbroker"
        threat_id = "2147768659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "atbroker: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 00 74 00 62 00 72 00 6f 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/start" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_A_2147768660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!rundll"
        threat_id = "2147768660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "rundll: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-80] 5c 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-80] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $n_5_3 = "\\filter.exe" wide //weight: -5
        $n_5_4 = "thor\\signatures" wide //weight: -5
        $n_5_5 = ".yms-textfilter" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_A_2147768661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!sc"
        threat_id = "2147768661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "sc: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 00 63 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-80] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 3d 00}  //weight: 2, accuracy: Low
        $x_2_2 = {73 00 63 00 2e 00 65 00 78 00 65 00 [0-80] 63 00 72 00 65 00 61 00 74 00 65 00 [0-80] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 3d 00}  //weight: 2, accuracy: Low
        $n_10_3 = "query" wide //weight: -10
        $n_10_4 = "sense" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_A_2147768662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!winrm"
        threat_id = "2147768662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "winrm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "winrm" wide //weight: 2
        $x_1_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 [0-240] 5c 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 [0-240] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspLolbinLaunch_B_2147768665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.B!rundll"
        threat_id = "2147768665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "rundll: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 [0-64] 6d 00 73 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
        $n_5_2 = "\\filter.exe" wide //weight: -5
        $n_5_3 = "thor\\signatures" wide //weight: -5
        $n_5_4 = ".yms-textfilter" wide //weight: -5
        $n_1000_5 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_6 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_A_2147768666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!wmic"
        threat_id = "2147768666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "wmic: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 6d 00 69 00 63 00 [0-96] 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-96] 63 00 61 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 6d 00 69 00 63 00 [0-96] 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-96] 67 00 65 00 74 00 [0-96] 62 00 72 00 69 00 65 00 66 00}  //weight: 1, accuracy: Low
        $x_1_3 = {77 00 6d 00 69 00 63 00 [0-96] 6e 00 6f 00 64 00 65 00 [0-96] 63 00 61 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $n_10_4 = {73 00 65 00 74 00 70 00 72 00 69 00 6f 00 72 00 69 00 74 00 79 00 [0-16] 61 00 62 00 6f 00 76 00 65 00 20 00 6e 00 6f 00 72 00 6d 00 61 00 6c 00}  //weight: -10, accuracy: Low
        $n_10_5 = "%-Dstartasuser%" wide //weight: -10
        $n_10_6 = "%StopRecording.bat%" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_A_2147768667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!script"
        threat_id = "2147768667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "script: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {63 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {6d 00 73 00 68 00 74 00 6d 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = "getobject" wide //weight: 2
        $x_2_6 = "exec" wide //weight: 2
        $x_1_7 = "script:" wide //weight: 1
        $n_3_8 = "tanium\\tanium" wide //weight: -3
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspLolbinLaunch_C_2147768688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.C!rundll"
        threat_id = "2147768688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "rundll: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 [0-64] 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 [0-64] 5f 00 72 00 75 00 6e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $n_1_2 = "Windows\\System32\\Firewall.cpl" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_D_2147768689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.D!rundll"
        threat_id = "2147768689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "rundll: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 [0-96] 73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_B_2147769386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.B!atbroker"
        threat_id = "2147769386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "atbroker: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "atbroker " wide //weight: 1
        $x_1_2 = "/start" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_B_2147769387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.B!sc"
        threat_id = "2147769387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "sc: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 00 63 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 [0-80] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 3d 00}  //weight: 2, accuracy: Low
        $x_2_2 = {73 00 63 00 2e 00 65 00 78 00 65 00 [0-80] 63 00 6f 00 6e 00 66 00 69 00 67 00 [0-80] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 3d 00}  //weight: 2, accuracy: Low
        $n_10_3 = "query" wide //weight: -10
        $n_10_4 = "airlock" wide //weight: -10
        $n_10_5 = "ADSync" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_D_2147778581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.D!credwiz"
        threat_id = "2147778581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "credwiz: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "credwiz.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLolbinLaunch_B_2147805335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.B!winrs"
        threat_id = "2147805335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "winrs: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {77 00 69 00 6e 00 72 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "winrs " wide //weight: 2
        $x_1_3 = " /r:" wide //weight: 1
        $x_1_4 = "/remote:" wide //weight: 1
        $n_100_5 = "\"program files\"" wide //weight: -100
        $n_100_6 = "\\program files\\" wide //weight: -100
        $n_100_7 = "-passwordkeyfile " wide //weight: -100
        $n_100_8 = "-passwordfile " wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

