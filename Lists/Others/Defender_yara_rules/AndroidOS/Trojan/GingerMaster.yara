rule Trojan_AndroidOS_GingerMaster_A_2147648821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GingerMaster.A"
        threat_id = "2147648821"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GingerMaster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "No SdCard, Can't Run!" ascii //weight: 1
        $x_1_2 = "MyHall::onServiceConnected" ascii //weight: 1
        $x_1_3 = {63 6c 69 65 6e 74 2e (67 6f 33 36 30 64 61|6d 75 73 74 6d 6f 62 69) 2e 63 6f 6d 2f 63 6c 69 65 6e 74 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 73 6f 66 74 26 73 6f 66 74 5f 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "select * from game_service_download order by soft_id desc" ascii //weight: 1
        $x_1_5 = "game_service_downloaddb.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_GingerMaster_B_2147657452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GingerMaster.B"
        threat_id = "2147657452"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GingerMaster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "No SdCard, Can't Run!" ascii //weight: 1
        $x_1_2 = "game_service_downloaddb.db" ascii //weight: 1
        $x_1_3 = {63 6c 69 65 6e 74 2e [0-9] 2e 63 6f 6d 2f 72 65 70 6f 72 74 2f 72 65 74 75 72 6e 5f 61 6c 65 72 74 2e 64 6f}  //weight: 1, accuracy: Low
        $x_1_4 = "pni ON game_package (package_name)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

