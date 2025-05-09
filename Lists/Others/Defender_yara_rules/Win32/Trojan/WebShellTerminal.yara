rule Trojan_Win32_WebShellTerminal_A_2147777724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebShellTerminal.A"
        threat_id = "2147777724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebShellTerminal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&echo [s]&cd&echo [e]" wide //weight: 1
        $x_1_2 = "&echo {s}&cd&echo {e}" wide //weight: 1
        $x_1_3 = "echo [s];(pwd).path;echo [e]" wide //weight: 1
        $x_1_4 = "&echo [a]&cd&echo [b]" wide //weight: 1
        $x_1_5 = "&echo [c]&cd&echo [d]" wide //weight: 1
        $x_1_6 = "&echo [f]&cd&echo [g]" wide //weight: 1
        $x_1_7 = "&echo ***^-^>&cd&echo ^<^-***" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_WebShellTerminal_B_2147829110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebShellTerminal.B"
        threat_id = "2147829110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebShellTerminal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cmd" wide //weight: 10
        $x_1_2 = "&cd&echo" wide //weight: 1
        $x_1_3 = "&cd&&echo" wide //weight: 1
        $x_1_4 = {65 00 63 00 68 00 6f 00 [0-2] 5b 00 [0-6] 5d 00 [0-2] 26 00 [0-2] 63 00 64 00 [0-2] 26 00 [0-2] 65 00 63 00 68 00 6f 00 [0-2] 5b 00 [0-6] 5d 00}  //weight: 1, accuracy: Low
        $n_50_5 = "Directory: &&cd&&echo" wide //weight: -50
        $n_50_6 = "WARP" wide //weight: -50
        $n_50_7 = "msedgewebview2.exe" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WebShellTerminal_C_2147895618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebShellTerminal.C"
        threat_id = "2147895618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebShellTerminal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = "/c cd /d" wide //weight: 10
        $n_50_3 = ".cmdret.dat" wide //weight: -50
        $n_50_4 = "svn update" wide //weight: -50
        $n_50_5 = "&&" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_WebShellTerminal_D_2147895810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebShellTerminal.D"
        threat_id = "2147895810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebShellTerminal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cmd" wide //weight: 10
        $x_10_2 = {26 00 65 00 63 00 68 00 6f 00 [0-2] 5b 00 ?? ?? 5d 00 26 00 63 00 64 00 26 00 65 00 63 00 68 00 6f 00 [0-2] 5b 00 ?? ?? 5d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WebShellTerminal_E_2147900969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebShellTerminal.E"
        threat_id = "2147900969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebShellTerminal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cmd" wide //weight: 10
        $x_10_2 = "/c pushd" wide //weight: 10
        $x_10_3 = {26 00 65 00 63 00 68 00 6f 00 ?? ?? 5b 00}  //weight: 10, accuracy: Low
        $n_50_4 = "&cd&echo" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

