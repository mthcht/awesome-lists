rule Ransom_Win32_Kitoles_A_2147723554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kitoles.A"
        threat_id = "2147723554"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kitoles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[/EXTENSION][TARGETS]" ascii //weight: 2
        $x_2_2 = "[BACKUPS][DRIVES][SHARES]" ascii //weight: 2
        $x_2_3 = "[/TASKNAME][AUTOEXEC][README]" ascii //weight: 2
        $x_1_4 = "Your files are now encrypted!" ascii //weight: 1
        $x_1_5 = "cryptolocker" ascii //weight: 1
        $x_1_6 = "bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Kitoles_A_2147723554_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kitoles.A"
        threat_id = "2147723554"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kitoles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your files are encrypted!" ascii //weight: 2
        $x_2_2 = "To decrypt files, please contact us by email:" ascii //weight: 2
        $x_2_3 = "decrypts@airmail.cc" ascii //weight: 2
        $x_2_4 = "HOW TO RECOVER ENCRYPTED FILES - decrypts@airmail.cc.TXT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Kitoles_AB_2147750265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kitoles.AB!MTB"
        threat_id = "2147750265"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kitoles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[/MESSAGE][MELT][TASKNAME]sysem.exe[/TASKNAME][AUTOEXEC][ONCEELEVATE][README]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

