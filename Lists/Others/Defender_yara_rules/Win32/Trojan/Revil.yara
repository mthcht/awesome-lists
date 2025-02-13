rule Trojan_Win32_Revil_SE_2147763323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Revil.SE!MTB"
        threat_id = "2147763323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Double run not allowed!" ascii //weight: 1
        $x_1_2 = "{EXT}-readme.txt" ascii //weight: 1
        $x_1_3 = "expand 32-byte kexpand 16-byte k" ascii //weight: 1
        $x_1_4 = {22 73 75 62 22 3a 22 [0-8] 22 2c 22 64 62 67 22 3a [0-8] 2c 22 65 74 22 3a [0-2] 2c 22 77 69 70 65 22 3a [0-5] 2c 22 77 68 74 22 3a 7b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Revil_SF_2147763403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Revil.SF!MTB!!Revil.gen!MTB"
        threat_id = "2147763403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        info = "Revil: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Double run not allowed!" ascii //weight: 1
        $x_1_2 = "{EXT}-readme.txt" ascii //weight: 1
        $x_1_3 = "\"fls\":[\"boot.ini\",\"iconcache.db\",\"bootsect.bak\"," ascii //weight: 1
        $x_1_4 = {22 73 75 62 22 3a 22 [0-8] 22 2c 22 64 62 67 22 3a [0-8] 2c 22 65 74 22 3a [0-2] 2c 22 77 69 70 65 22 3a [0-5] 2c 22 77 68 74 22 3a 7b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Revil_SG_2147763898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Revil.SG!MTB!!Revil.gen!MTB"
        threat_id = "2147763898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        info = "Revil: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\"nname\":\"{EXT}-readme.txt\"" ascii //weight: 10
        $x_10_2 = "QQBsAGwAIABvAGYAIAB5AG8AdQByACAAZgBpAGwAZQBzACAAYQByAGUAIABlAG4AYwByAHkAcAB0AGUAZAAhAA0" ascii //weight: 10
        $x_1_3 = "\"svc\":[\"" ascii //weight: 1
        $x_1_4 = "\"nbody\":\"" ascii //weight: 1
        $x_1_5 = "\"wipe\":" ascii //weight: 1
        $x_1_6 = "\"wfld\":[" ascii //weight: 1
        $x_1_7 = "\"prc\":" ascii //weight: 1
        $x_1_8 = "\"dmn\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Revil_SJ_2147763928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Revil.SJ!MTB"
        threat_id = "2147763928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{EXT}-readme.txt" ascii //weight: 10
        $x_10_2 = "QQBsAGwAIABvAGYAIAB5AG8AdQByACAAZgBpAGwAZQBzACAAYQByAGUAIABlAG4AYwByAHkAcAB0AGUAZAAhAA0" ascii //weight: 10
        $x_1_3 = "\"svc\":[\"" ascii //weight: 1
        $x_1_4 = "\"nbody\":\"" ascii //weight: 1
        $x_1_5 = "\"wipe\":" ascii //weight: 1
        $x_1_6 = "\"wfld\":[" ascii //weight: 1
        $x_1_7 = "\"prc\":" ascii //weight: 1
        $x_1_8 = "\"dmn\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

