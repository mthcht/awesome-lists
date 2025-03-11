rule Trojan_AndroidOS_BrowBot_A_2147894750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BrowBot.A"
        threat_id = "2147894750"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BrowBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/data_13/install_13.php" ascii //weight: 2
        $x_2_2 = "senderphone_13" ascii //weight: 2
        $x_2_3 = "SmsReceiverActivity_13" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BrowBot_B_2147895223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BrowBot.B"
        threat_id = "2147895223"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BrowBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "apinetcom.com/data" ascii //weight: 2
        $x_2_2 = "a8p.net/tqfXDn" ascii //weight: 2
        $x_2_3 = "sourcez_15" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BrowBot_B_2147895223_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BrowBot.B"
        threat_id = "2147895223"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BrowBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://a8p.net/tqfXDn" ascii //weight: 1
        $x_1_2 = "$DeviceModel_16" ascii //weight: 1
        $x_1_3 = "senderphone_16" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BrowBot_C_2147895760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BrowBot.C"
        threat_id = "2147895760"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BrowBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 73 6f 75 72 63 65 7a 5f ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 64 61 74 61 5f ?? ?? 2f 69 6e 64 65 78 5f ?? ?? 2e 70 68 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 53 6d 73 52 65 63 65 69 76 65 72 41 63 74 69 76 69 74 79 5f ?? ?? 3b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BrowBot_H_2147896292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BrowBot.H"
        threat_id = "2147896292"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BrowBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://www.apinetcom.com/data_16/index_16.php" ascii //weight: 2
        $x_2_2 = "homepageUrl_16" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BrowBot_A_2147899827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BrowBot.A!MTB"
        threat_id = "2147899827"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BrowBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/browser/download21" ascii //weight: 1
        $x_1_2 = "SmsReceiverActivity" ascii //weight: 1
        $x_1_3 = "a8p.net/tqfXDn" ascii //weight: 1
        $x_1_4 = "ttps://www.apinetcom.com/data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BrowBot_B_2147910829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BrowBot.B!MTB"
        threat_id = "2147910829"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BrowBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "a8p.net/tqfXDn" ascii //weight: 1
        $x_1_2 = "credentialsLauncher_" ascii //weight: 1
        $x_1_3 = {64 61 74 61 5f ?? ?? 2f 69 6e 73 74 61 6c 6c 5f ?? ?? 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_4 = {53 6d 73 52 65 63 65 69 76 65 72 5f ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_5 = {63 68 65 63 6b 65 72 5f ?? ?? 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_BrowBot_D_2147935648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BrowBot.D!MTB"
        threat_id = "2147935648"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BrowBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/data_28/install_28.php" ascii //weight: 1
        $x_1_2 = "/data_28/smsapi_28.php" ascii //weight: 1
        $x_1_3 = "credentialsLauncher_" ascii //weight: 1
        $x_1_4 = "senderphone_" ascii //weight: 1
        $x_1_5 = "sourceapisapp.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

