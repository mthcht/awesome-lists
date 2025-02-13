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

