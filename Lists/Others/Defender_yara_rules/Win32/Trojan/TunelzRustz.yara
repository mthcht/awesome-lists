rule Trojan_Win32_TunelzRustz_A_2147917902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TunelzRustz.A!MTB"
        threat_id = "2147917902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TunelzRustz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src/net/tcp/socket.rs" ascii //weight: 1
        $x_1_2 = "src/proxy.rs" ascii //weight: 1
        $x_1_3 = "Pingackpayload" ascii //weight: 1
        $x_1_4 = "encoded settings" ascii //weight: 1
        $x_1_5 = "encoded ping" ascii //weight: 1
        $x_1_6 = "encoded go_away" ascii //weight: 1
        $x_1_7 = "encoded window_update" ascii //weight: 1
        $x_1_8 = "encoded reset" ascii //weight: 1
        $x_1_9 = "src/runtime/task/core.rs" ascii //weight: 1
        $x_1_10 = "Loaded  proxies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

