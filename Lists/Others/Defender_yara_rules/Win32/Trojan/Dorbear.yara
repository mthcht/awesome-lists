rule Trojan_Win32_Dorbear_A_2147708669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dorbear.A"
        threat_id = "2147708669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorbear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "passDs5Bu9Te7" ascii //weight: 2
        $x_1_2 = "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAsrGnWG3XPW4tO8tRLhF+XQyuM5ZcLl9tIsnlMyIUXwpt" ascii //weight: 1
        $x_1_3 = "9Kh4E3czOCDxQ== rsa-key-20131121" ascii //weight: 1
        $x_1_4 = "dropbear" ascii //weight: 1
        $x_1_5 = {eb 4d 8d 45 f4 89 44 24 04 a1 ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? c7 44 24 04 ?? ?? ?? ?? 89 04 24 89 c3 e8 ?? ?? ?? ?? 85 c0 74 16 c7 44 24 04 01 00 00 00 c7 04 24 00 00 00 00 e8 ?? ?? ?? ?? eb 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

