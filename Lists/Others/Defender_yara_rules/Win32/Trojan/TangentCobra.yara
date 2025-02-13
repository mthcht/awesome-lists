rule Trojan_Win32_TangentCobra_A_2147724724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TangentCobra.A!dha"
        threat_id = "2147724724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TangentCobra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 0f b6 14 04 41 ff c0 03 d7 0f b6 ca 8a 14 0c 43 32 14 13 41 88 12 49 ff c2 49 ff c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TangentCobra_B_2147724725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TangentCobra.B!dha"
        threat_id = "2147724725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TangentCobra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1B1440D90FC9BCB46A9AC96438FEEA8B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TangentCobra_C_2147724726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TangentCobra.C!dha"
        threat_id = "2147724726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TangentCobra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nautilus-service.dll" ascii //weight: 1
        $x_1_2 = "oxygen.dll" ascii //weight: 1
        $x_1_3 = "config_listen.system" ascii //weight: 1
        $x_1_4 = "ctx.system" ascii //weight: 1
        $x_1_5 = "3FDA3998-BEF5-426D-82D8-1A71F29ADDC3" ascii //weight: 1
        $x_1_6 = "C:\\ProgramData\\Microsoft\\Windows\\Caches\\{%s}.2.ver0x0000000000000001.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

