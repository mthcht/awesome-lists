rule Backdoor_MSIL_Torwofun_B_2147695622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Torwofun.B"
        threat_id = "2147695622"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Torwofun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "winsofting.ru" wide //weight: 4
        $x_4_2 = "key=TrlO81ZdSApIUNGD7120MCVXrtewppwqehdMgTsA6039" wide //weight: 4
        $x_4_3 = {3c 4d 6f 64 75 6c 65 3e 00 53 79 73 74 65 6d 41 75 74 6f 72 75 6e 2e 65 78 65}  //weight: 4, accuracy: High
        $x_4_4 = {3c 4d 6f 64 75 6c 65 3e 00 69 6e 73 74 61 6c 6c 65 72 5f 69 6e 73 74 61 6c 6c 63 75 62 65 2e 65 78 65}  //weight: 4, accuracy: High
        $x_3_5 = "Update\\UnLoad.exe" wide //weight: 3
        $x_3_6 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 53 00 79 00 73 00 74 00 65 00 6d 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 65 00 78 00 65 00}  //weight: 3, accuracy: High
        $x_2_7 = "StatsLocker\\SystemAutorun" ascii //weight: 2
        $x_2_8 = "get_IsRunningTOR" ascii //weight: 2
        $x_2_9 = {53 79 73 74 65 6d 41 75 74 6f 72 75 6e 2e 65 78 65 00 53 74 61 72 74}  //weight: 2, accuracy: High
        $x_2_10 = {2e 65 78 65 00 73 74 61 72 74 [0-6] 00 72 75 6e 57 49 4e}  //weight: 2, accuracy: Low
        $x_2_11 = "unloads.ru" wide //weight: 2
        $x_1_12 = "\\runWIN\\" wide //weight: 1
        $x_1_13 = "\\system app\\" wide //weight: 1
        $x_1_14 = "AntiSpy.exe" wide //weight: 1
        $x_1_15 = "installcube.exe" ascii //weight: 1
        $x_1_16 = "UnLoad_TorProject" wide //weight: 1
        $x_1_17 = "get_SystemAutorun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

