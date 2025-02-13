rule Ransom_Win32_Kattisrypt_A_2147721670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kattisrypt.A"
        threat_id = "2147721670"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kattisrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "]DECRYPTION.TXT[" ascii //weight: 1
        $x_2_2 = "[/MESSAGE][TASKNAME]guide.exe[/TASKNAME]" ascii //weight: 2
        $x_1_3 = ".oled" ascii //weight: 1
        $x_1_4 = "black.mirror@qq.com" ascii //weight: 1
        $x_1_5 = {5b 53 41 4e 44 42 4f 58 45 53 5d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5b 2f 54 41 53 4b 4e 41}  //weight: 1, accuracy: Low
        $x_1_6 = {5b 57 41 49 54 44 41 54 45 5d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5b 2f 54 41 53 4b 4e 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

