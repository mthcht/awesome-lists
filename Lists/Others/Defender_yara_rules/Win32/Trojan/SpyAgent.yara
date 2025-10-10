rule Trojan_Win32_SpyAgent_2147753605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyAgent!MSR"
        threat_id = "2147753605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\haleng.exe" ascii //weight: 1
        $x_1_2 = "http://uehge4g6Gh.2ihsfa.com/api/?sid=0&key=8e56becd9ed99edf57d41e1dd73118c5" ascii //weight: 1
        $x_1_3 = "D:\\workspace\\workspace_c\\Gj7eU93o7gGhg_19\\Release\\Gj7eU93o7gGhg_19.pdb" ascii //weight: 1
        $x_1_4 = "jfiag3g_gg.exe" ascii //weight: 1
        $x_1_5 = "fj4ghga23_fsa.txt" ascii //weight: 1
        $x_1_6 = "DELETE FROM cookie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyAgent_MD_2147806284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyAgent.MD!MTB"
        threat_id = "2147806284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".boot" ascii //weight: 1
        $x_1_2 = ".JJVQJMA" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\Common Files\\ThinkVantage Fingerprint Software\\Drivers\\smihlp.sys" ascii //weight: 1
        $x_1_4 = "/dumpstatus" ascii //weight: 1
        $x_1_5 = "\\SystemRoot\\system32\\BOOTVI" ascii //weight: 1
        $x_1_6 = "Ubisoft Connect" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyAgent_MB_2147808459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyAgent.MB!MTB"
        threat_id = "2147808459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "exportData" ascii //weight: 1
        $x_1_2 = "Stealer.exe" ascii //weight: 1
        $x_1_3 = {8a 46 01 8b cf 88 45 0b 8d 45 0b 53 50 e8 ?? ?? ?? ?? 8a 46 02 8b cf 88 45 0b 8d 45 0b 53 50 e8 ?? ?? ?? ?? 8a 46 03 8b cf 88 45 0b 8d 45 0b 53 50 e8 ?? ?? ?? ?? 8a 46 04 8b cf 88 45 0b 8d 45 0b 53 50 e8}  //weight: 1, accuracy: Low
        $x_1_4 = "passwords" ascii //weight: 1
        $x_1_5 = "cookies" ascii //weight: 1
        $x_1_6 = "crypto" ascii //weight: 1
        $x_1_7 = "ShiftLeft" ascii //weight: 1
        $x_1_8 = "ShiftRight" ascii //weight: 1
        $x_1_9 = "HttpOpenRequestW" ascii //weight: 1
        $x_1_10 = "Username:" ascii //weight: 1
        $x_1_11 = "ReadCookie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyAgent_RPL_2147809591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyAgent.RPL!MTB"
        threat_id = "2147809591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ungaina" ascii //weight: 1
        $x_1_2 = ".refutab" ascii //weight: 1
        $x_1_3 = ".implume" ascii //weight: 1
        $x_1_4 = ".turbody" ascii //weight: 1
        $x_1_5 = ".calvini" ascii //weight: 1
        $x_1_6 = ".becircl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyAgent_R_2147899226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyAgent.R!MTB"
        threat_id = "2147899226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "62.204.41.192" wide //weight: 1
        $x_1_2 = "ip{NAN}t.Sh" wide //weight: 1
        $x_1_3 = "rosoft\\Windows" wide //weight: 1
        $x_1_4 = "WScript.Shell" wide //weight: 1
        $x_1_5 = "$TC.replace('{NAN}'" wide //weight: 1
        $x_1_6 = "RED.oo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyAgent_AMTB_2147954752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyAgent!AMTB"
        threat_id = "2147954752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http.Open(\"POST\", \"http://zx.pe/bp.php\", false)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

