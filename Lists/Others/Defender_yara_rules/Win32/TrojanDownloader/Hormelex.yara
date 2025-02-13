rule TrojanDownloader_Win32_Hormelex_G_2147689128_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hormelex.G"
        threat_id = "2147689128"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hormelex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "3DE418CF060673E6032DDD0EC9709A4CFD2CD70FCAB2599253D70F3FEA113B988EB454995F9D5A88A8FF20B87A" ascii //weight: 3
        $x_2_2 = "darlynegocios.com/editar/maxplugs.zip" ascii //weight: 2
        $x_1_3 = "0E2BCD0332E10DC77FBB5F95B45EC3709F5D" ascii //weight: 1
        $x_1_4 = "7D9847EB22D40738D702729342EF" ascii //weight: 1
        $x_1_5 = "52EF15C96D9F41E219CB7DEF1BDB0E" ascii //weight: 1
        $x_1_6 = "9AB7658DA9518C44FD231333D176" ascii //weight: 1
        $x_1_7 = "C6628EAC5DCD75A947" ascii //weight: 1
        $x_1_8 = "D371994AF82E1ACA0B36" ascii //weight: 1
        $x_1_9 = "6F8AAD638EA953C56392B5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Hormelex_H_2147693403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hormelex.H"
        threat_id = "2147693403"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hormelex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 68 61 6d 31 30 31 30 [0-32] 2e 7a 69 70}  //weight: 1, accuracy: Low
        $x_1_2 = "9AB7658DA9518C44FD231333D176" ascii //weight: 1
        $x_1_3 = "C6628EAC5DCD75A947" ascii //weight: 1
        $x_1_4 = "D371994AF82E1ACA0B36" ascii //weight: 1
        $x_1_5 = "6F8AAD638EA953C56392B5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Hormelex_I_2147694137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hormelex.I"
        threat_id = "2147694137"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hormelex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 89 20 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ba ?? ?? ?? ?? 8b c3 8b 08 ff 51 30 8d 45 fc b9 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {63 68 61 6d 31 30 31 30 [0-32] 2e 7a 69 70}  //weight: 1, accuracy: Low
        $x_1_3 = "9AB7658DA9518C44FD231333D176" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

