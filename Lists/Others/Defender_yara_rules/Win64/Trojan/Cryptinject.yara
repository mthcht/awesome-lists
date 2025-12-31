rule Trojan_Win64_Cryptinject_QC_2147920337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cryptinject.QC!MTB"
        threat_id = "2147920337"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP/qsxbkx.exe" ascii //weight: 1
        $x_1_2 = "rundll32.exe %s,rundll" ascii //weight: 1
        $x_1_3 = "powershell.exe -Command" ascii //weight: 1
        $x_1_4 = "gsjsoig.lnk" ascii //weight: 1
        $x_1_5 = "$WshShell.CreateShortcut($shortcutPath)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cryptinject_YBA_2147930737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cryptinject.YBA!MTB"
        threat_id = "2147930737"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {33 45 df 21 c2 8a 55 ec 48 03 5d e8 03 5d c4 48 8b 45 ac 0f b7 d2}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cryptinject_YBC_2147930775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cryptinject.YBC!MTB"
        threat_id = "2147930775"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {48 2b c8 49 0f af cf 0f b6 44 0d 8f 43 32 44 18 fc 41 88 40 fc 41 8d 42 ff 48 63 c8 48 8b c3 48 f7 e1}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cryptinject_YBE_2147932089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cryptinject.YBE!MTB"
        threat_id = "2147932089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 44 0d 87 43 32 44 0b ?? 41 88 41 fb 41 8d 42 ff 48 63 c8 48 8b c3 48 f7 e1}  //weight: 10, accuracy: Low
        $x_1_2 = {48 2b c8 49 0f af cc 0f b6 44 0d ?? 42 32 44 0e fb 41 88 41 fd 41 8d 42 01 48 63 c8 48 8b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cryptinject_YBG_2147960338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cryptinject.YBG!MTB"
        threat_id = "2147960338"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8d 40 80 0f b6 0a 41 2a c8 41 ff c0 32 c8 88 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

