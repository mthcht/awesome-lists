rule Trojan_Win64_StealerC_RZ_2147921603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealerC.RZ!MTB"
        threat_id = "2147921603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Go build ID: \"AVZ073cOjL7Fgp4uZZae" ascii //weight: 2
        $x_2_2 = "main.(*ExtractBrowserProfile).zipUserData" ascii //weight: 2
        $x_2_3 = ".extractBrowserData" ascii //weight: 2
        $x_2_4 = ".copyUserData.func1" ascii //weight: 2
        $x_1_5 = ".killChromeProcesses.func1" ascii //weight: 1
        $x_1_6 = "Ivrsjzivjwdqlcwrmbuoowiebijwjkag" ascii //weight: 1
        $x_1_7 = "ouuhltqrdxkxcfwnokiraowiforuavef.func1" ascii //weight: 1
        $x_1_8 = "jbrgznwtqgjusbrusdagfssikogtkauw.func1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealerC_ARR_2147954803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealerC.ARR!MTB"
        threat_id = "2147954803"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 f7 ee 48 d1 ?? 48 8d 0c 52 48 8d 0c 4a 48 29 ce 0f 57 db f2 48 0f 2a de}  //weight: 20, accuracy: Low
        $x_10_2 = {48 89 d7 49 f7 ec 48 d1 ?? 4d 89 e7 49 c1 fc ?? 4c 29 e2 4c 8d 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealerC_ARR_2147954803_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealerC.ARR!MTB"
        threat_id = "2147954803"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {49 89 f8 48 8d bc 24 ?? ?? ?? ?? 49 89 c1 31 c0 f3 48 ab 31 c9 31 ff 41 ba}  //weight: 20, accuracy: Low
        $x_10_2 = {49 f7 e5 4c 01 ea 48 d1 da 48 c1 ea ?? 48 89 d0 48 c1 e2 ?? 48 29 c2 4c 89 e8 49 29 d5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

