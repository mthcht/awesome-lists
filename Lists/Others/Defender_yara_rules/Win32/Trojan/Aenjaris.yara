rule Trojan_Win32_Aenjaris_ROC_2147744628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aenjaris.ROC!MTB"
        threat_id = "2147744628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aenjaris"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "./tmp.err" wide //weight: 1
        $x_1_2 = "wmiintegrator.exe" wide //weight: 1
        $x_1_3 = "wmihostwin.exe" wide //weight: 1
        $x_1_4 = "wmimic.exe" wide //weight: 1
        $x_1_5 = "wmisecure.exe" wide //weight: 1
        $x_1_6 = "nocreatefolder" wide //weight: 1
        $x_1_7 = "svchost.exe" wide //weight: 1
        $x_1_8 = "explorer.exe" wide //weight: 1
        $x_1_9 = "services.exe" wide //weight: 1
        $x_1_10 = ".*(?=[ ]{1,}disco|disk(?:[\\r\\n ]|$))" wide //weight: 1
        $x_1_11 = "\\[ID\\](.*)?\\[\\/ID\\]" wide //weight: 1
        $x_1_12 = "\\[COMMAND\\](.*)?\\[\\/COMMAND\\]" wide //weight: 1
        $x_1_13 = "\\[EXEC_EXE\\](.*)?\\[\\/EXEC_EXE\\]" wide //weight: 1
        $x_1_14 = "unkilable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Aenjaris_GVA_2147948841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aenjaris.GVA!MTB"
        threat_id = "2147948841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aenjaris"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a b0 00 10 40 00 c0 ce df 80 f6 ab 80 ee a4 88 b0 00 10 40 00 40 81 f8 9b 31 02 00 75 e2 61 68 1d f2 40 00}  //weight: 2, accuracy: High
        $x_1_2 = {0a fc 84 04 fb df f4 a6 87 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Aenjaris_AB_2147954453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aenjaris.AB!MTB"
        threat_id = "2147954453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aenjaris"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9e 86 f8 3b 95 fa 3a 99 c0 0e d8 e8 35 ?? ?? ?? ?? 99 f2 0e d8 e8 30 4b f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

