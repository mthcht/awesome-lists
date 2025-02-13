rule Trojan_Win64_Strela_GA_2147917187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strela.GA!MTB"
        threat_id = "2147917187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strela"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 c7 44 24 28 88 13 00 00 48 c7 44 24 20 00 00 00 00 41 b9 10 00 00 00 31 c9 4c 89 ?? 4d 89}  //weight: 10, accuracy: Low
        $x_1_2 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9}  //weight: 1, accuracy: High
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Strela_GA_2147917187_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strela.GA!MTB"
        threat_id = "2147917187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strela"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" ascii //weight: 20
        $x_10_2 = "/server.php" ascii //weight: 10
        $x_10_3 = "/out.php" ascii //weight: 10
        $x_5_4 = "mscoree.dll" ascii //weight: 5
        $x_5_5 = "AppPolicyGetProcessTerminationMethod" ascii //weight: 5
        $x_1_6 = "POST" ascii //weight: 1
        $x_1_7 = "\\Thunderbird\\Profiles" ascii //weight: 1
        $x_1_8 = "Mozilla/" ascii //weight: 1
        $x_1_9 = "IMAP User" ascii //weight: 1
        $x_1_10 = "IMAP Server" ascii //weight: 1
        $x_1_11 = "IMAP Password" ascii //weight: 1
        $x_1_12 = "%s%s\\logins.json" ascii //weight: 1
        $x_1_13 = "%s%s\\key4.db" ascii //weight: 1
        $x_1_14 = "MessageBoxTimeoutA" ascii //weight: 1
        $x_1_15 = "RtlPcToFileHeader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Strela_GB_2147917188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strela.GB!MTB"
        threat_id = "2147917188"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strela"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 c7 44 24 28 88 13 00 00 48 c7 44 24 20 00 00 00 00 41 b9 10 00 00 00 31 c9}  //weight: 10, accuracy: High
        $x_1_2 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9}  //weight: 1, accuracy: High
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Strela_GC_2147926150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strela.GC!MTB"
        threat_id = "2147926150"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strela"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 b9 10 00 00 00 4c 8d 05 8f 6a 01 00 48 8d 15 88 6a 01 00 33 c9}  //weight: 10, accuracy: High
        $x_10_2 = {41 b9 10 00 00 00 4c 8d 05 3f 6a 01 00 48 8d 15 38 6a 01 00 33 c9}  //weight: 10, accuracy: High
        $x_1_3 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9}  //weight: 1, accuracy: High
        $x_1_4 = "Entry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

