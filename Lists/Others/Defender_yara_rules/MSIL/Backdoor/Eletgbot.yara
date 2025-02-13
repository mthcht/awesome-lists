rule Backdoor_MSIL_Eletgbot_A_2147888246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Eletgbot.A"
        threat_id = "2147888246"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Eletgbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "L2MgdGltZW91dCB7MH0=" ascii //weight: 1
        $x_1_2 = "UG93ZXJzaGVsbA==" ascii //weight: 1
        $x_1_3 = "QW1zaVNjYW5CdWZmZXI=" wide //weight: 1
        $x_1_4 = "YW1zaS5kbGw=" wide //weight: 1
        $x_1_5 = "TelegramToken" ascii //weight: 1
        $x_1_6 = "VXVpZEZyb21TdHJpbmdB" ascii //weight: 1
        $x_1_7 = "DQoz77iP4oOjIEZpbGUgPSA=(aHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

