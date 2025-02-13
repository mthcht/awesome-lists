rule Backdoor_Win32_ProxyBot_C_2147642413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ProxyBot.C"
        threat_id = "2147642413"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ProxyBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "Sandman\\Cpp projects\\SocksProxy" ascii //weight: 5
        $x_4_2 = "_ProxyDll.dll" ascii //weight: 4
        $x_5_3 = {8d 85 f8 ef ff ff 50 6a 00 c7 47 04 80 4a 5d 05 ff 15}  //weight: 5, accuracy: Low
        $x_5_4 = {8b f8 83 ff 31 59 7e 0f e8}  //weight: 5, accuracy: Low
        $x_5_5 = {c1 6c 24 08 03 33 c9 39 4c 24 08 76 1b 8b 44 24 04 8d 04 c8}  //weight: 5, accuracy: High
        $x_2_6 = "ip=%s&port=%d&guid=%s&version=%s&pass=%s&" ascii //weight: 2
        $x_2_7 = "ARE_YOU_ALIVE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_ProxyBot_D_2147649704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ProxyBot.D"
        threat_id = "2147649704"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ProxyBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "BPR:Bot id:%x(%d) tim:%d %s" ascii //weight: 10
        $x_10_2 = "Loose bot delay:%d" ascii //weight: 10
        $x_1_3 = "strikeCount" ascii //weight: 1
        $x_1_4 = "botCount" ascii //weight: 1
        $x_1_5 = "botProxy" ascii //weight: 1
        $x_1_6 = "portSearcher" ascii //weight: 1
        $x_1_7 = "emailSearcher" ascii //weight: 1
        $x_1_8 = "proxyChecker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_ProxyBot_D_2147649704_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ProxyBot.D"
        threat_id = "2147649704"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ProxyBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?port_IP=%d&port_PI=%d&ver=" ascii //weight: 1
        $x_1_2 = "|edu|gov|info|int|jobs|mil|" ascii //weight: 1
        $x_1_3 = {5c 2a 2e 64 6c 6c 00 00 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 6d 61 69 6c 53 65 61 72 63 68 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 6d 77 63 6f 72 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {62 6f 74 50 72 6f 78 79 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 4f 54 5f 49 50 00}  //weight: 1, accuracy: High
        $x_1_8 = "Kill25" ascii //weight: 1
        $x_1_9 = ":555/sorttable.js></script>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_Win32_ProxyBot_E_2147653879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ProxyBot.E"
        threat_id = "2147653879"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ProxyBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/getiplist.php" ascii //weight: 1
        $x_1_2 = "/get_reserved_servers.php" ascii //weight: 1
        $x_1_3 = "/updateexe.php" ascii //weight: 1
        $x_1_4 = "/botinfo.ph" ascii //weight: 1
        $x_1_5 = "%s?guid=%s&version=%d.%d.%d" ascii //weight: 1
        $x_1_6 = "guid=%s&version=%s&installtype=%s" ascii //weight: 1
        $x_1_7 = "ip=%s&guid=%s&version=%s&pass=%s" ascii //weight: 1
        $x_1_8 = "_ProxyDll.dll" ascii //weight: 1
        $x_1_9 = "ARE_YOU_ALIVE" ascii //weight: 1
        $x_1_10 = {48 45 4c 4f [0-5] 4d 41 49 4c [0-5] 46 52 4f 4d [0-5] 52 43 50 54 [0-5] 54 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

