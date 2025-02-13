rule Ransom_Win32_Erebus_A_2147719893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Erebus.A!rsm"
        threat_id = "2147719893"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Erebus"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 57 8b 7e 10 3b f9 72 ?? 8b 55 0c 8b c7 2b c1 3b c2 77 ?? 83 7e 14 10 89 4e 10 72 ?? 8b 06 5f c6 04 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 57 3d 11 27 00 00 0f 8f 0a 0c 00 00 0f 84 ed 0b 00 00 83 c0 fd 3d ec 00 00 00 0f 87 af 1b 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "vssadmin delete shadows" ascii //weight: 1
        $x_1_4 = "wmic logicaldisk where drivetype=" ascii //weight: 1
        $x_1_5 = {2e 61 72 77 00 00 00 00 2e 62 61 79 00 00 00 00 2e 63 64 72 00 00 00 00 2e 63 65 72}  //weight: 1, accuracy: High
        $x_1_6 = "Recover my files</a>" wide //weight: 1
        $x_1_7 = "> Crypted Files : <" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Erebus_A_2147719896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Erebus.A!!Erebus.A!rsm"
        threat_id = "2147719896"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Erebus"
        severity = "Critical"
        info = "Erebus: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 57 8b 7e 10 3b f9 72 ?? 8b 55 0c 8b c7 2b c1 3b c2 77 ?? 83 7e 14 10 89 4e 10 72 ?? 8b 06 5f c6 04 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 57 3d 11 27 00 00 0f 8f 0a 0c 00 00 0f 84 ed 0b 00 00 83 c0 fd 3d ec 00 00 00 0f 87 af 1b 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "vssadmin delete shadows" ascii //weight: 1
        $x_1_4 = "wmic logicaldisk where drivetype=" ascii //weight: 1
        $x_1_5 = {2e 61 72 77 00 00 00 00 2e 62 61 79 00 00 00 00 2e 63 64 72 00 00 00 00 2e 63 65 72}  //weight: 1, accuracy: High
        $x_1_6 = "Recover my files</a>" wide //weight: 1
        $x_1_7 = "> Crypted Files : <" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

