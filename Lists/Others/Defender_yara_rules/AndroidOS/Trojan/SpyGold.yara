rule Trojan_AndroidOS_SpyGold_A_2147647286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyGold.A"
        threat_id = "2147647286"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyGold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UploadFiles.aspx?askId=1&uid=" ascii //weight: 1
        $x_1_2 = "allotWorkTask.aspx?no=" ascii //weight: 1
        $x_1_3 = "zjphonecall.txt" ascii //weight: 1
        $x_1_4 = {52 65 67 69 73 74 55 69 64 [0-1] 2e 61 73 70 78 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SpyGold_B_2147653389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyGold.B"
        threat_id = "2147653389"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyGold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/GoldDream/TingTing" ascii //weight: 1
        $x_1_2 = "lebar.gicp.net/update_soft." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

