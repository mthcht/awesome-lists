rule Trojan_Win32_Disstl_DD_2147785331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Disstl.DD!MTB"
        threat_id = "2147785331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "y|w;iev762hpp" ascii //weight: 3
        $x_3_2 = "WriteProcessMemory" ascii //weight: 3
        $x_3_3 = "GetProcAddress" ascii //weight: 3
        $x_3_4 = "www.crypter" ascii //weight: 3
        $x_3_5 = "Phs9eohWxvmrkE" ascii //weight: 3
        $x_3_6 = "WtX5EnXMG" ascii //weight: 3
        $x_3_7 = "GetLongPathNameA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Disstl_AP_2147798303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Disstl.AP!MTB"
        threat_id = "2147798303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendhookfile.exe" ascii //weight: 1
        $x_1_2 = "C:/temp/WebBrowserPassView.exe" ascii //weight: 1
        $x_1_3 = "C:/temp/Passwords.txt" ascii //weight: 1
        $x_1_4 = "Browser Password!" ascii //weight: 1
        $x_1_5 = "Passwords.txt not found" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Disstl_CG_2147808325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Disstl.CG!MTB"
        threat_id = "2147808325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 92 45 c2 1b b8 30 48 0a f7 eb 05 9a 04 08 64 48 eb 03}  //weight: 1, accuracy: High
        $x_1_2 = {bb 1c 52 90 eb 01 b7 e9 c1 01 00 00 eb 02 f3 02 8b 02 eb 01 f3 33 42 04 72 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

