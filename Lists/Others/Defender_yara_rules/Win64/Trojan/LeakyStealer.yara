rule Trojan_Win64_LeakyStealer_YBE_2147957511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LeakyStealer.YBE!MTB"
        threat_id = "2147957511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LeakyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8a 04 2b 41 30 03 49 ff c3 49 8b 82 80 00 00 00 48 ff c0 83 e0 3f 49 89 82}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LeakyStealer_YBE_2147957511_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LeakyStealer.YBE!MTB"
        threat_id = "2147957511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LeakyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Beacon starting" ascii //weight: 1
        $x_1_2 = "Polymorphism applied" ascii //weight: 1
        $x_1_3 = "Browser history uploaded " ascii //weight: 1
        $x_1_4 = "Got persistent Bot ID from volume serial" ascii //weight: 1
        $x_1_5 = "Admin privileges" ascii //weight: 1
        $x_1_6 = "Polymorphic engine starting" ascii //weight: 1
        $x_1_7 = "Executing downloaded file" ascii //weight: 1
        $x_1_8 = "Bitcoin" ascii //weight: 1
        $x_1_9 = "Electrum" ascii //weight: 1
        $x_1_10 = "Exodus" ascii //weight: 1
        $x_1_11 = "Atomic Wallet" ascii //weight: 1
        $x_1_12 = "Sparrow Wallet" ascii //weight: 1
        $x_1_13 = "BitPay Wallet" ascii //weight: 1
        $x_1_14 = "Opera Software\\Opera Stable\\History" ascii //weight: 1
        $x_1_15 = "Google\\Chrome\\User Data\\Default\\History" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

