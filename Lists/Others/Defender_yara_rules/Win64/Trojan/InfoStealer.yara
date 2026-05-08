rule Trojan_Win64_InfoStealer_NI_2147923389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.NI!MTB"
        threat_id = "2147923389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 15 ea 19 04 00 48 89 0c 24 44 0f 11 7c 24 08 48 89 54 24 18 48 89 44 24 20 44 0f 11 7c 24 28 e8 ?? ?? ?? ?? 45 0f 57 ff 4c 8b 35 00 50 9d 00}  //weight: 3, accuracy: Low
        $x_1_2 = "portgetaddrinfowtransmitfile" ascii //weight: 1
        $x_1_3 = "BitappCoin" ascii //weight: 1
        $x_1_4 = "masterkey_db" ascii //weight: 1
        $x_1_5 = "Fromicmpigmpftpspop3smtpdial" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_InfoStealer_EM_2147955891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.EM!MTB"
        threat_id = "2147955891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {50 45 00 00 64 86 0f 00 2c 91 4f 66 00 00 00 00 00 00 00 00 f0 00 22 00 0b 02 0e 00 00 4c a5 08}  //weight: 3, accuracy: High
        $x_3_2 = "electron.exe.pdb" ascii //weight: 3
        $x_3_3 = "PDF Editor" ascii //weight: 3
        $x_1_4 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 31 00 2e 00 30 00 2e 00 38}  //weight: 1, accuracy: High
        $x_1_5 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 31 00 2e 00 30 00 2e 00 32}  //weight: 1, accuracy: High
        $x_1_6 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 31 00 2e 00 30 00 2e 00 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_InfoStealer_PAA_2147960281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.PAA!MTB"
        threat_id = "2147960281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 83 f9 04 74 2b 45 31 d2 49 83 fa 40 74 11 46 8a 1c 12 47 32 1c 10 46 88 1c 11 49 ff c2 eb e9 49 ff c1 49 83 c0 40 48 83 c2 40 48 83 c1 40 eb cf}  //weight: 2, accuracy: High
        $x_3_2 = {74 10 8a 8c 04 b0 00 00 00 41 30 0c 04 48 ff c0 eb eb}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_InfoStealer_P_2147963568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.P!MTB"
        threat_id = "2147963568"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AmsiBypass..." wide //weight: 1
        $x_1_2 = "DisableETW..." wide //weight: 1
        $x_1_3 = "CallStackSpoof::Initialize..." wide //weight: 1
        $x_1_4 = "SleepObfuscation::Initialize..." wide //weight: 1
        $x_1_5 = "NtdllUnhook::RestoreNtdll..." wide //weight: 1
        $x_1_6 = "Metamorphic::MorphTextSection..." wide //weight: 1
        $x_1_7 = "polymorphic_init..." wide //weight: 1
        $x_1_8 = "[SANDBOX] VM/sandbox detected" wide //weight: 1
        $x_1_9 = "[T] wallets done" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_InfoStealer_PAB_2147966176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.PAB!MTB"
        threat_id = "2147966176"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[A2] Done collecting," ascii //weight: 1
        $x_1_2 = "\\Exodus\\exodus.wallet" ascii //weight: 1
        $x_1_3 = "\\Coinomi\\Coinomi\\wallets" ascii //weight: 1
        $x_1_4 = "\\Microsoft\\Edge\\User Data" ascii //weight: 1
        $x_1_5 = "\\BitPay\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_6 = "\\Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_7 = "Waterfox\\ProfilesThunderbird\\Profileslogins.jsonkey4.dbkey3.dbcookies.sqliteformhistory.sqliteplaces.sqlite" ascii //weight: 1
        $x_1_8 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_9 = "Cookies-walSELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies" ascii //weight: 1
        $x_1_10 = "once_lock.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_InfoStealer_PAC_2147966715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.PAC!MTB"
        threat_id = "2147966715"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 d2 f7 f7 8d 42 01 41 0f b6 04 04 41 30 04 08 48 83 c1 01 44 39 c9 89 c8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_InfoStealer_PAD_2147966716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.PAD!MTB"
        threat_id = "2147966716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {3b 4c 24 78 89 c8 73 14 31 d2 f7 f6 8d 42 01 8a 04 03 41 30 44 0d 00 48 ff c1 eb e4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_InfoStealer_PAE_2147967248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.PAE!MTB"
        threat_id = "2147967248"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 d2 41 f7 f1 8d 42 06 41 0f b6 44 05 00 30 04 0f 48 83 c1 01 39 d9 89 c8 72 e5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_InfoStealer_PAF_2147967249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.PAF!MTB"
        threat_id = "2147967249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 39 d0 73 18 4c 8d 41 01 48 ff c0 8a 09 30 48 ff 4d 39 f8 4c 89 c1 49 0f 43 ca eb e3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_InfoStealer_PAG_2147968499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.PAG!MTB"
        threat_id = "2147968499"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 89 d0 83 e0 1f 0f b6 84 04 c0 00 00 00 43 32 04 11 43 88 04 13 49 83 c2 01 4d 39 d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_InfoStealer_PAH_2147968879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.PAH!MTB"
        threat_id = "2147968879"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 84 24 80 00 00 00 ff c0 48 98 48 8b 4c 24 70 0f b6 04 01 0f b6 4c 24 60 33 c1 48 63 8c 24 80 00 00 00 88 84 0c 0c 02}  //weight: 3, accuracy: High
        $x_2_2 = {42 4a 42 ea 6a 42 62 b0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

