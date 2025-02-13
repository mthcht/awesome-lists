rule Trojan_MacOS_WireLurker_B_2147748739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/WireLurker.B!MTB"
        threat_id = "2147748739"
        type = "Trojan"
        platform = "MacOS: "
        family = "WireLurker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "comeinbaby.com" ascii //weight: 1
        $x_1_2 = "/tmp/sfbase.dylib" ascii //weight: 1
        $x_1_3 = "/tmp/sms.db" ascii //weight: 1
        $x_1_4 = "/tmp/AddressBook.sqlitedb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_WireLurker_C_2147749024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/WireLurker.C!MTB"
        threat_id = "2147749024"
        type = "Trojan"
        platform = "MacOS: "
        family = "WireLurker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/t.lock" ascii //weight: 1
        $x_1_2 = "MailServiceAgentHelper.plist" ascii //weight: 1
        $x_1_3 = "/usr/share/tokenizer/ja" ascii //weight: 1
        $x_1_4 = "/usr/bin/stty5.11.pl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_WireLurker_D_2147750961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/WireLurker.D!MTB"
        threat_id = "2147750961"
        type = "Trojan"
        platform = "MacOS: "
        family = "WireLurker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/t.lock" ascii //weight: 1
        $x_1_2 = "/bin/launchctl load -wF /System/Library/LaunchDaemons/com.apple.MailServiceAgentHelper.plist" ascii //weight: 1
        $x_1_3 = "systemkeychain-helper" ascii //weight: 1
        $x_1_4 = "/tmp/up/update.zip" ascii //weight: 1
        $x_1_5 = "/usr/share/tokenizer/ja" ascii //weight: 1
        $x_1_6 = "com.apple.appstore.PluginHelper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

