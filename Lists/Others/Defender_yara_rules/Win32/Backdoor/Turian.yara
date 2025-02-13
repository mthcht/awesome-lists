rule Backdoor_Win32_Turian_A_2147823008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turian.A!dha"
        threat_id = "2147823008"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turian"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "tripinindian.com" ascii //weight: 10
        $x_10_2 = "osendata.com" ascii //weight: 10
        $x_1_3 = "sOFtWArE\\MIcrOsOft\\WindOwS\\CurRentVeRsiOn\\RuN" wide //weight: 1
        $x_1_4 = "ReG aDd %s%s /v \"%S\" /t REG_SZ /d \"%S\" /f" wide //weight: 1
        $x_1_5 = "ReG dEletE %s%s /v \"%S\" /f" wide //weight: 1
        $x_1_6 = "tmp.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

