rule Backdoor_AndroidOS_Fakengry_A_2147654483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Fakengry.A"
        threat_id = "2147654483"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Fakengry"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=&task=window&downloadType=silentdownload&flagid=-101&softuid=" ascii //weight: 1
        $x_1_2 = "l.anzhuo7.com:9055/ca.log" ascii //weight: 1
        $x_1_3 = ":8097/getxml.do" ascii //weight: 1
        $x_1_4 = "i22/angrybirds/cccccc" ascii //weight: 1
        $x_1_5 = {03 e8 af b7 e7 a8 8d e4 be af 00 08 e6 95 b0 e6 8d ae e6 b8 85 e7 90 86 e4 b8 ad 2e 2e 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_AndroidOS_Fakengry_A_2147829163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Fakengry.A!MTB"
        threat_id = "2147829163"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Fakengry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 05 0f 04 d5 55 ff 00 d8 06 04 01 48 06 0f 06 d5 66 ff 00 d8 07 04 02 48 07 0f 07 d5 77 ff 00 62 08 ?? ?? e2 09 05 02 dd 09 09 3f 48 08 08 09 4f 08 01 03 d8 08 03 01 62 09 ?? ?? e0 05 05 04 e2 0a 06 04 b6 a5 dd 05 05 3f 48 05 09 05 4f 05 01 08 d8 05 03 02 62 08 ?? ?? e0 06 06 02 e2 09 07 06 b6 96 dd 06 06 3f 48 06 08 06 4f 06 01 05 d8 05 03 03 62 06 ?? ?? dd 07 07 3f 48 06 06 07 4f 06 01 05 d8 04 04 03 d8 03 03 04 28 aa}  //weight: 1, accuracy: Low
        $x_1_2 = {12 3e 12 03 13 0d 73 00 12 2c 12 1b 21 f0 dc 00 00 03 39 00 12 00 21 f1 da 01 01 04 db 01 01 03 23 11 ?? ?? 21 f2 b1 02 01 34 34 24 10 00 2b 00 b7 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

