rule Trojan_Win32_Skeeyah_D_2147709416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skeeyah.D!bit"
        threat_id = "2147709416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skeeyah"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 0c 8a 0c 0f 8b 45 08 30 0c 18 8d 47 01 99 f7 7d fc 8b fa ff d6 43 3b 5d 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Skeeyah_E_2147712175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skeeyah.E!bit"
        threat_id = "2147712175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skeeyah"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7c 24 2c 31 fb 33 5c 24 04 8b 7c 24 10 31 fb 89 d8 88 44 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Skeeyah_Y_2147741346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skeeyah.Y!MTB"
        threat_id = "2147741346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skeeyah"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\SENIN\\VIRUS\\" wide //weight: 1
        $x_1_2 = "\\NoPorn.exe" wide //weight: 1
        $x_1_3 = "JAUHI_PORNOGRAFI" wide //weight: 1
        $x_1_4 = "Policies\\System\\DisableRegistryTools" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Skeeyah_NS_2147893193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skeeyah.NS!MTB"
        threat_id = "2147893193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skeeyah"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_crt_debugger_hook" ascii //weight: 1
        $x_1_2 = "_invoke_watson" ascii //weight: 1
        $x_1_3 = "object_hook" ascii //weight: 1
        $x_1_4 = "utf_32_decode" ascii //weight: 1
        $x_1_5 = "tokenize.pycPK" ascii //weight: 1
        $x_1_6 = "cmd.pycPK" ascii //weight: 1
        $x_1_7 = "HVJU" ascii //weight: 1
        $x_1_8 = "py2exe" ascii //weight: 1
        $x_1_9 = "uy*:M" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

