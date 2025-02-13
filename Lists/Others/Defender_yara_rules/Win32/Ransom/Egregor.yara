rule Ransom_Win32_Egregor_A_2147764791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Egregor.A!MTB"
        threat_id = "2147764791"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Egregor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%Greetings2target%" ascii //weight: 1
        $x_1_2 = "%egregor_data%" ascii //weight: 1
        $x_1_3 = "--EGREGOR--" ascii //weight: 1
        $x_1_4 = "I do not fear your threats!" ascii //weight: 1
        $x_1_5 = "msftesql.exe;sqlagent.exe;sqlbrowser.exe;sqlwriter.exe;" ascii //weight: 1
        $x_1_6 = "Your network was ATTACKED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Egregor_XZ_2147768914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Egregor.XZ!MTB"
        threat_id = "2147768914"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Egregor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOUD !!!!..." ascii //weight: 1
        $x_1_2 = "Elon Musk 2024! To the future!!!" ascii //weight: 1
        $x_1_3 = "C:\\ddddss\\eeerrr\\iufyhfj.py" ascii //weight: 1
        $x_1_4 = "CryptStringToBinaryA" ascii //weight: 1
        $x_1_5 = "--loud" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Egregor_YZ_2147768915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Egregor.YZ!MTB"
        threat_id = "2147768915"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Egregor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 04 08 8b 4d b8 0f b6 4c 0d bc 31 c8 88 c2 [0-255] 8b 45 10 8b 4d b8 88 14 08}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 4d b8 0f b6 4c 0d bc 31 c8 88 c2 8b 45 10 8b 4d b8 88 14 08 8b 45 b8 83 c0 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Egregor_SU_2147770331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Egregor.SU!MTB"
        threat_id = "2147770331"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Egregor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllInstall" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
        $x_1_4 = "Crypt32.dll" ascii //weight: 1
        $x_1_5 = "CryptStringToBinaryA" ascii //weight: 1
        $x_1_6 = "expand 32-byte kexpand 16-byte k" ascii //weight: 1
        $x_5_7 = "\\fasm\\INCLUDE\\API\\fasm.pdb" ascii //weight: 5
        $x_5_8 = ":\\hehe\\cybercom.pdb" ascii //weight: 5
        $x_5_9 = ":\\sc\\p\\sed.pdb" ascii //weight: 5
        $x_5_10 = ":\\defaultlog\\installator\\debug\\dss.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Egregor_SG_2147771167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Egregor.SG!MTB"
        threat_id = "2147771167"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Egregor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 5c 48 65 69 6c 20 45 67 72 65 67 6f 72 5c [0-8] 5c 66 69 63 6b 65 72 2e 70 79}  //weight: 1, accuracy: Low
        $x_1_2 = "--dubisteinmutterficker" ascii //weight: 1
        $x_1_3 = "This is dummy messagebox" ascii //weight: 1
        $x_1_4 = "Deleting failed successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Egregor_PA_2147771462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Egregor.PA!MTB"
        threat_id = "2147771462"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Egregor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\threat\\researches\\no\\jokes\\the\\best\\writer.py" wide //weight: 1
        $x_1_2 = "[09*y7093ry84tr7y8u9yt4g8fh474ds" ascii //weight: 1
        $x_1_3 = "0498yths" ascii //weight: 1
        $x_1_4 = "Boris" wide //weight: 1
        $x_1_5 = "--mthfckbtch" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Egregor_PAA_2147775609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Egregor.PAA!MTB"
        threat_id = "2147775609"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Egregor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--dubisteinmutterficker" wide //weight: 1
        $x_1_2 = "Egregor" wide //weight: 1
        $x_1_3 = "Interesting module" ascii //weight: 1
        $x_1_4 = "Hello world" ascii //weight: 1
        $x_1_5 = ".pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

