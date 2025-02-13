rule Trojan_AndroidOS_Donot_A_2147783475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Donot.A"
        threat_id = "2147783475"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Donot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WappHolder.txt" ascii //weight: 1
        $x_1_2 = "thirteen: location gps" ascii //weight: 1
        $x_1_3 = "setnewalram" ascii //weight: 1
        $x_1_4 = "DB_PATHENTER" ascii //weight: 1
        $x_1_5 = "select * from WappMap where Map=" ascii //weight: 1
        $x_1_6 = ".amr::Added" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Donot_B_2147813370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Donot.B"
        threat_id = "2147813370"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Donot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fIOeTNMvibZ29Otolc35sQ==" ascii //weight: 1
        $x_1_2 = "nXRaaJxcK/DI2iLLQCeoGg==" ascii //weight: 1
        $x_1_3 = ".amr::Added" ascii //weight: 1
        $x_1_4 = "yg9aVzdXVbut6ucY6MUJyg==" ascii //weight: 1
        $x_1_5 = "jBxPiASmlLspb7YlyiZYwA==" ascii //weight: 1
        $x_1_6 = "3fplWvI5A2A7dd+cWPpUvQ==" ascii //weight: 1
        $x_1_7 = "pbr5gbbz+24aiJpqXI+L5Q==" ascii //weight: 1
        $x_1_8 = "rHMWj2IWq1w0nBdQ8NoppA==" ascii //weight: 1
        $x_1_9 = "occuStyAgzJ9qkHxV5djGg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_AndroidOS_Donot_C_2147849489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Donot.C"
        threat_id = "2147849489"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Donot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AppKillCheckService" ascii //weight: 2
        $x_2_2 = "tbl_all_contact_list" ascii //weight: 2
        $x_2_3 = "table_group_roster" ascii //weight: 2
        $x_2_4 = "roster_list_new_message_count" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Donot_D_2147849490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Donot.D"
        threat_id = "2147849490"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Donot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ShareableContactsTemp" ascii //weight: 2
        $x_2_2 = "KYLK00.txt" ascii //weight: 2
        $x_2_3 = "RoomDbIns_Impl" ascii //weight: 2
        $x_2_4 = "ChatListDao_Impl" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

