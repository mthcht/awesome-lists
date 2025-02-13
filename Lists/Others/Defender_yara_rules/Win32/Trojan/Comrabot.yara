rule Trojan_Win32_Comrabot_A_2147651526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Comrabot.A"
        threat_id = "2147651526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Comrabot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 0f 8b 51 04 8b 4c 3a ?? 8b 55 ?? 8b 01 8b 40 ?? 33 f6 56 52 8b 55 ?? 52 ff d0}  //weight: 2, accuracy: Low
        $x_1_2 = "Getting task from URL:" ascii //weight: 1
        $x_1_3 = "01eqyc.com" ascii //weight: 1
        $x_1_4 = "Decrypted size:%d [%s]" ascii //weight: 1
        $x_1_5 = "Comrade VER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

