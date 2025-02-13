rule Trojan_MSIL_CryptTrickldr_A_2147769295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptTrickldr.A!MTB"
        threat_id = "2147769295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptTrickldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 73 65 72 3d 24 28 5b 54 45 58 54 2e 45 6e 63 4f 44 69 6e 67 5d 3a 3a 55 4e 49 63 6f 64 65 2e 47 45 54 53 74 52 69 4e 47 28 5b 43 6f 6e 76 45 52 74 5d 3a 3a 46 72 4f 6d 42 61 53 45 36 34 53 54 52 49 4e 67 28 27 61 41 42 30 41 48 51 41 63 41 41 36 41 43 38 41 4c 77 [0-48] 27 29 29 29 3b 24 74 3d 27 2f 61 64 6d 69 6e 2f 67 65 74 2e 70 68 70 27 3b}  //weight: 1, accuracy: Low
        $x_1_2 = {24 4b 3d 5b 53 59 53 74 65 4d 2e 54 65 58 74 2e 45 6e 43 4f 64 69 6e 47 5d 3a 3a 41 53 43 49 49 2e 47 65 54 42 59 54 65 73 28 27 [0-48] 27 29 3b 24 52 3d 7b 24 44 2c 24 4b 3d 24 41 72 67 73 3b 24 53 3d 30 2e 2e 32 35 35 3b 30 2e 2e 32 35 35 7c 25 7b 24 4a 3d 28 24 4a 2b 24 53 5b 24 5f 5d 2b 24 4b 5b 24 5f 25 24 4b 2e 43 6f 55 6e 54 5d 29 25 32 35 36 3b}  //weight: 1, accuracy: Low
        $x_1_3 = "$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I]," ascii //weight: 1
        $x_1_4 = "$S[$H]=$S[$H],$S[$I];$_-bxOr$S[($S[$I]+$S[$H])%256]}};" ascii //weight: 1
        $x_1_5 = {24 44 61 54 61 3d 24 [0-16] 2e 44 6f 77 6e 6c 6f 41 64 44 61 54 41 28 24 53 45 72 2b 24 74 29 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptTrickldr_A_2147770147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptTrickldr.A!ibt"
        threat_id = "2147770147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptTrickldr"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "enablescriptblockinvocationlogging" ascii //weight: 1
        $x_1_2 = "windows\\powershell\\scriptb'+'locklogging'" ascii //weight: 1
        $x_1_3 = "webclient;$u='mozilla/5.0" ascii //weight: 1
        $x_1_4 = "[text.encoding]::unicode.getstring([convert]::frombase64string('aab0ahqacaa6ac8alw" ascii //weight: 1
        $x_1_5 = "/admin/get.php" ascii //weight: 1
        $x_1_6 = ".proxy=[system.net.webrequest]" ascii //weight: 1
        $x_1_7 = ".headers.add('user-agent'," ascii //weight: 1
        $x_1_8 = "$_-bxor$" ascii //weight: 1
        $x_1_9 = ".downloaddata(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

