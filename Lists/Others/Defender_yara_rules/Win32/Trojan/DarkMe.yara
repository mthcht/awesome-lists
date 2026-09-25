rule Trojan_Win32_DarkMe_MBWQ_2147931704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkMe.MBWQ!MTB"
        threat_id = "2147931704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkMe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 3e 14 00 00 f0 30 00 00 ff ff ff 09 00 00 00 01 00 00 00 02 00 01 00 e9 00 00 00 64 2b 00 11 cc 2c 00 11 dc 28 00 11 24 ed eb 10 2e ed eb}  //weight: 2, accuracy: High
        $x_1_2 = {39 ed eb 10 3a ed eb 10 00 00 f4 01 00 00 c6 40 14 00 00 00 00 00 20 45 00 11 10 3b 28 11 00 14 00 00 08 50 28 11 76 26 00 11 00 50 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkMe_GV_2147978808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkMe.GV!MTB"
        threat_id = "2147978808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkMe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_RUNDOS" ascii //weight: 1
        $x_1_2 = "= \"msiexec" ascii //weight: 1
        $x_1_3 = "= \" /i " ascii //weight: 1
        $x_1_4 = "= \"https://" ascii //weight: 1
        $x_1_5 = "= \"/propi.msi" ascii //weight: 1
        $x_1_6 = "= \" /quiet" ascii //weight: 1
        $x_1_7 = "= \" /norestart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkMe_GC_2147978832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkMe.GC!MTB"
        threat_id = "2147978832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkMe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "41505044415441" ascii //weight: 1
        $x_1_2 = "5C436F6D706F6E656E7473466F6C6465725C636F6D70616E792E636572" ascii //weight: 1
        $x_1_3 = "4E6F626F6479676F696E676F7574" ascii //weight: 1
        $x_1_4 = "5C4D6963726F736F66745C636C737061636B2E657865" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkMe_GD_2147978846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkMe.GD!MTB"
        threat_id = "2147978846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkMe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KillTimer" ascii //weight: 1
        $x_1_2 = "\\root\\SecurityCenter2" ascii //weight: 1
        $x_1_3 = "Wallets:" ascii //weight: 1
        $x_1_4 = "\\Blockchain Wallet" ascii //weight: 1
        $x_1_5 = "\\MyEtherWallet" ascii //weight: 1
        $x_1_6 = "\\nkbihfbeogaeaoehlefnkodbefgpgknn" ascii //weight: 1
        $x_1_7 = "NeverEndingStoryWithYou" ascii //weight: 1
        $x_1_8 = "soft\\Windows\\Exp" ascii //weight: 1
        $x_1_9 = "tuttidati" ascii //weight: 1
        $x_1_10 = "onlywayhere23" ascii //weight: 1
        $x_1_11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

