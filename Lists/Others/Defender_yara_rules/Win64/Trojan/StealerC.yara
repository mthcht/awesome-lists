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

