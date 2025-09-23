rule Trojan_Win32_AmsiBypazz_A_2147945457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AmsiBypazz.A!MTB"
        threat_id = "2147945457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AmsiBypazz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[Ref].Assembly.GetType" wide //weight: 1
        $x_1_2 = ".getfield" wide //weight: 1
        $x_1_3 = {69 00 6e 00 69 00 74 00 66 00 61 00 69 00 6c 00 65 00 64 00 [0-16] 24 00}  //weight: 1, accuracy: Low
        $x_1_4 = {76 00 61 00 6c 00 75 00 65 00 [0-16] 24 00 6e 00 75 00 6c 00 6c 00 2c 00 24 00 74 00 72 00 75 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AmsiBypazz_GGA_2147948555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AmsiBypazz.GGA!MTB"
        threat_id = "2147948555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AmsiBypazz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "::GetExecutingAssembly" wide //weight: 1
        $x_1_2 = "System.Management.Automation.AmsiUtils" wide //weight: 1
        $x_1_3 = "System.Reflection.Assembly" wide //weight: 1
        $x_1_4 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_5 = "amsiInit" wide //weight: 1
        $x_1_6 = "GetField(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AmsiBypazz_GGB_2147948556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AmsiBypazz.GGB!MTB"
        threat_id = "2147948556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AmsiBypazz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[char]([int]$" wide //weight: 1
        $x_1_2 = "-bxor $" wide //weight: 1
        $x_1_3 = "-join" wide //weight: 1
        $x_1_4 = ".Split(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AmsiBypazz_B_2147949405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AmsiBypazz.B!MTB"
        threat_id = "2147949405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AmsiBypazz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[char][int] $_)" wide //weight: 1
        $x_1_2 = "[string]::join('" wide //weight: 1
        $x_1_3 = ".write($" wide //weight: 1
        $x_1_4 = ".getbytes($" wide //weight: 1
        $x_1_5 = "|foreachobject{$_" wide //weight: 1
        $x_1_6 = ".path +" wide //weight: 1
        $x_1_7 = ".getstream()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AmsiBypazz_Z_2147952744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AmsiBypazz.Z!MTB"
        threat_id = "2147952744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AmsiBypazz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".invoke($" wide //weight: 1
        $x_1_2 = "byte[]]$" wide //weight: 1
        $x_1_3 = "getmethod(" wide //weight: 1
        $x_1_4 = "::load($" wide //weight: 1
        $x_1_5 = ".split" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

