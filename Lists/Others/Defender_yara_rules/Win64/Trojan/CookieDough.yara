rule Trojan_Win64_CookieDough_A_2147959188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CookieDough.A"
        threat_id = "2147959188"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CookieDough"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "skj8q1fxetgkhd" ascii //weight: 1
        $x_1_2 = "@D8mtNlyeZqGlWOoNvLBKuj" ascii //weight: 1
        $x_1_3 = "@VnW9eISDj9Hwg8GaX5" ascii //weight: 1
        $x_1_4 = "esiTh+SO7ZGYQzjKJBH5d/3g6G3lS1ugrhVgavf0SqJHuiqnjZUkY/uslqL6dSNc" ascii //weight: 1
        $x_1_5 = "name=\"atok\"\\\\s*value=\"(.*?)" ascii //weight: 1
        $x_1_6 = "<kbd>L SHIFT</kbd>" ascii //weight: 1
        $x_1_7 = "<kbd>Attn</kbd>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

