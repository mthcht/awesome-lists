rule Trojan_AndroidOS_RewardSteal_H_2147837255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RewardSteal.H"
        threat_id = "2147837255"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdjsskfdksfksdkfjkkshkfhkshk" ascii //weight: 1
        $x_1_2 = "com.abc898d.webmaster" ascii //weight: 1
        $x_1_3 = "+918637579741" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_RewardSteal_F_2147839945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RewardSteal.F!MTB"
        threat_id = "2147839945"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/in/reward" ascii //weight: 1
        $x_1_2 = "rewards/Restarter" ascii //weight: 1
        $x_1_3 = "rewards/YourService" ascii //weight: 1
        $x_1_4 = "content://sms" ascii //weight: 1
        $x_1_5 = "deliverselfnotifications" ascii //weight: 1
        $x_1_6 = "CVV must be of 3 digits." ascii //weight: 1
        $x_1_7 = "@lucky.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_RewardSteal_G_2147851298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RewardSteal.G!MTB"
        threat_id = "2147851298"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.example.rewardsapp" ascii //weight: 1
        $x_1_2 = "card_number" ascii //weight: 1
        $x_1_3 = "storeCardInfo" ascii //weight: 1
        $x_1_4 = "DEV_Reward_Pointss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_RewardSteal_H_2147901500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RewardSteal.H!MTB"
        threat_id = "2147901500"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hello/uwer/hello/hello/google/is/the/best/MainActivity" ascii //weight: 1
        $x_1_2 = "getMessageBody" ascii //weight: 1
        $x_1_3 = "SaveMessageService" ascii //weight: 1
        $x_1_4 = "getOriginatingAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_RewardSteal_Y_2147933112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RewardSteal.Y!MTB"
        threat_id = "2147933112"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {12 00 72 20 8e cb 04 00 0a 00 71 10 b5 cb 00 00 0c 00 72 20 79 ec 05 00 0c 00 1f 00 bf 1b 22 01 84 1f 12 12 71 10 dc f6 04 00 0a 03 70 30 ba f0 21 03 6e 10 ca f0 01 00 0c 01 6e 10 ff e1 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {d8 02 01 ff 72 20 8e cb 13 00 0a 01 71 10 b5 cb 01 00 0c 01 71 10 b5 cb 00 00 0c 00 72 30 7d ec 14 00 0c 00 1f 00 b8 1b 6e 10 95 cb 00 00 0a 00 01 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_RewardSteal_X_2147933284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RewardSteal.X!MTB"
        threat_id = "2147933284"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 03 20 00 6e 20 39 28 31 00 0c 04 1f 04 0d 07 6e 20 40 28 94 00 0a 05 38 05 11 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 53 e9 03 22 03 b1 02 70 10 cd 0c 03 00 5b 53 ec 03 5c 51 ed 03 5b 56 d8 03 62 06 49 05 6e 20 85 0c 62 00 62 06 47 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

