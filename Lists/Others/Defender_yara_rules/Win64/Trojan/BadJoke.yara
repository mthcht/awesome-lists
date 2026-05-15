rule Trojan_Win64_BadJoke_KK_2147947322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadJoke.KK!MTB"
        threat_id = "2147947322"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b c1 83 e0 03 42 0f b6 04 30 30 04 0b 48 ff c1 8b 44 24 48 48 3b c8 72}  //weight: 20, accuracy: High
        $x_10_2 = {66 31 18 48 83 c0 02 48 3b c2 75 f4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BadJoke_ARR_2147958505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadJoke.ARR!MTB"
        threat_id = "2147958505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {29 ca 8d 0c 92 c1 e1 ?? 29 c8 89 c2 0f 84}  //weight: 15, accuracy: Low
        $x_10_2 = {45 89 f1 41 b8 ?? ?? ?? ?? 48 89 f1 89 6c 24 48 ba}  //weight: 10, accuracy: Low
        $x_5_3 = "C:\\Windows\\System32\\conhost.exe --headless C:\\Windows\\System32\\wlrmdr.exe -s 60000 -f 2 -t \"%s\" -m \"%s\"" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BadJoke_GPB_2147964631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadJoke.GPB!MTB"
        threat_id = "2147964631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_cleanup%d" ascii //weight: 1
        $x_1_2 = "rundll32.exe %s,InstallHinfSection %s 128 %s" ascii //weight: 1
        $x_1_3 = "Command.com /c %s" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_5 = "cmd /c \"dangerous.bat\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BadJoke_MK_2147965661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadJoke.MK!MTB"
        threat_id = "2147965661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {0f b6 85 04 01 00 00 0f b6 8d 24 01 00 00 c1 e1 08 0b c1 0f b6 8d 44 01 00 00 c1 e1 10 0b c1 44 8b c0 ba 05}  //weight: 20, accuracy: High
        $x_15_2 = {8b 85 64 01 00 00 ff c0 89 85 64 01 00 00 8b 85 64 01 00 00 8b 8d 08 01 00 00 2b c8 8b c1 b9 08 00 00 00 48 6b c9 00 89 84 0d 38 01}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BadJoke_ND_2147969426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadJoke.ND!MTB"
        threat_id = "2147969426"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 85 c9 0f 84 9d 00 00 00 e8 a7 fe ff ff 48 85 db be 16 00 00 00 74 16 48 8b 0b 48 85 c9 74 0e 48 83 f9 ff 74 32 81 39 ed f0 b1 ba 74 1b 48 8b 0d 98 91 08 00 48 85 c9}  //weight: 2, accuracy: High
        $x_1_2 = "rd /s" ascii //weight: 1
        $x_1_3 = "/q C:\\" ascii //weight: 1
        $x_1_4 = "gcc-shmeH" ascii //weight: 1
        $x_1_5 = "start qwq.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

