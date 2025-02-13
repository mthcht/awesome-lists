rule Trojan_Win32_Ubot_A_2147659515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ubot.A"
        threat_id = "2147659515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ubot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "trol=trol&userandpc=%s&admin=%s&os=%s&cpu=%s&gpu=%s&battery=%.1s&id=%s&version=%s&dotnet=%s" ascii //weight: 1
        $x_1_2 = "/bots1/run.php" ascii //weight: 1
        $x_1_3 = "fc5dfcad738358a0cbb59bf0478340a1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

